#pragma once
#include "submodules/cstd/lib.c"

#include "configuration.c"
#include "uv_utils.c"

#define BLOCK_SIZE (1UL << 14)

typedef struct {
  uv_write_t req;
  uv_buf_t buf;
  void *data;
} WriteRequest;

typedef struct {
  uv_fs_t req;
  uv_buf_t bufs[32 /* FIXME */];
  u64 bufs_len;
  void *data;
} FsWriteRequest;

[[maybe_unused]] [[nodiscard]] static int do_write(uv_stream_t *stream,
                                                   PgString data,
                                                   PgAllocator *allocator,
                                                   uv_write_cb cb, void *ctx) {
  WriteRequest *wq =
      pg_alloc(allocator, sizeof(WriteRequest), _Alignof(WriteRequest), 1);
  wq->buf = string_to_uv_buf(data);
  wq->req.data = wq;
  wq->data = ctx;

  return uv_write(&wq->req, stream, &wq->buf, 1, cb);
}

typedef struct {
  u32 val;
} PieceIndex;

typedef struct {
  u32 val;
} BlockForPieceIndex;

typedef struct {
  u32 val;
} BlockForDownloadIndex;

PG_OK(BlockForDownloadIndex) BlockForDownloadIndexOk;

typedef struct {
  PgString data;
  BlockForPieceIndex block;
} BlockDownload;

typedef struct {
  PieceIndex piece;
  BlockDownload block_downloads[32 /* FIXME */];
  u64 block_downloads_len;

  // Bitfield.
  u8 blocks_have[4 /* FIXME */];
  u8 blocks_downloading[4 /* FIXME */];
} PieceDownload;

PG_DYN(PieceDownload) PieceDownloadDyn;
PG_SLICE(PieceDownload) PieceDownloadSlice;

typedef struct {
  // Bookkeeping.
  PgString pieces_have;
  u32 pieces_have_count;
  PgString pieces_downloading;

  // (Derived) constants from the torrent file.
  u32 pieces_count;
  u32 blocks_count;
  u32 blocks_per_piece_max;
  u64 piece_length;
  u64 total_size;
  // All hashes (20 bytes long) for pieces, in one big string.
  PgString pieces_hash;

  // TODO: Multiple files.

  PgFileDescriptor file;
  PgLogger *logger;
  PgRng *rng;
  PgArena arena;

  Configuration *cfg;

  // Counters.
  u64 concurrent_downloads_count;
  u64 peers_active_count;

} Download;

[[nodiscard]] static u32 download_compute_pieces_count(u64 piece_length,
                                                       u64 total_file_size) {
  u64 res = pg_div_ceil(total_file_size, piece_length);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

[[nodiscard]] static u32
download_compute_max_blocks_per_piece_count(u64 piece_length) {
  u64 res = pg_div_ceil(piece_length, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

[[nodiscard]] [[maybe_unused]] static Download
download_make(PgLogger *logger, PgRng *rng, Configuration *cfg,
              u64 piece_length, u64 total_size, PgString pieces_hash,
              PgFileDescriptor file /* TODO: multiple files */) {
  PG_ASSERT(0 == pieces_hash.len % PG_SHA1_DIGEST_LENGTH);
  PG_ASSERT(pieces_hash.len > 0);

  Download download = {0};
  download.logger = logger;
  download.rng = rng;
  download.cfg = cfg;
  download.piece_length = piece_length;
  download.total_size = total_size;
  download.pieces_hash = pieces_hash;
  download.file = file;

  // (Derived) constants from the torrent file.
  download.pieces_count =
      download_compute_pieces_count(piece_length, total_size);
  download.blocks_count = (u32)pg_div_ceil(total_size, BLOCK_SIZE);
  download.blocks_per_piece_max =
      download_compute_max_blocks_per_piece_count(piece_length);

  u64 pieces_bitfield_size = pg_div_ceil(download.pieces_count, 8);
  download.arena = pg_arena_make_from_virtual_mem(2 * pieces_bitfield_size);
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&download.arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  download.pieces_have = pg_string_make(pieces_bitfield_size, allocator);
  download.pieces_downloading = pg_string_make(pieces_bitfield_size, allocator);

  PG_ASSERT(download.blocks_per_piece_max > 0);

  return download;
}

[[nodiscard]] static i32 block_downloads_sort(const void *va, const void *vb) {
  BlockDownload *a = (BlockDownload *)va;
  BlockDownload *b = (BlockDownload *)vb;

  if (a->block.val < b->block.val) {
    return -1;
  } else if (a->block.val == b->block.val) {
    return 0;
  } else {
    return 1;
  }
}

[[nodiscard]] static u32 download_compute_piece_length(Download *download,
                                                       PieceIndex piece) {
  PG_ASSERT(piece.val < download->pieces_count);
  PG_ASSERT(download->pieces_count > 0);
  PG_ASSERT(download->piece_length <= UINT32_MAX);

  u64 res = (piece.val + 1) == download->pieces_count
                ? download->total_size - piece.val * download->piece_length
                : download->piece_length;

  PG_ASSERT(res <= UINT32_MAX);
  PG_ASSERT(res <= download->piece_length);

  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static u32
download_compute_blocks_count_for_piece(Download *download, PieceIndex piece) {
  PG_ASSERT(piece.val * download->piece_length <= download->total_size);

  u32 pieces_count = download_compute_pieces_count(download->piece_length,
                                                   download->total_size);
  PG_ASSERT(pieces_count > 0);

  if (piece.val < pieces_count - 1) {
    PG_ASSERT(download->blocks_per_piece_max > 0);
    return download->blocks_per_piece_max;
  }

  u64 rem = download->total_size - piece.val * download->piece_length;

  u64 res = pg_div_ceil(rem, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  PG_ASSERT(res <= download->blocks_per_piece_max);
  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static BlockForDownloadIndex
download_convert_block_for_piece_to_block_for_download(
    Download *download, PieceIndex piece, BlockForPieceIndex block_for_piece) {
  PG_ASSERT(piece.val < download->pieces_count);
  PG_ASSERT(block_for_piece.val < download->blocks_per_piece_max);

  u32 res = piece.val * download->blocks_per_piece_max + block_for_piece.val;
  PG_ASSERT(res < download->blocks_count);

  return (BlockForDownloadIndex){res};
}

[[maybe_unused]] [[nodiscard]] static BlockForPieceIndex
download_convert_block_for_download_to_block_for_piece(
    Download *download, PieceIndex piece,
    BlockForDownloadIndex block_for_download) {
  PG_ASSERT(piece.val < download->pieces_count);
  PG_ASSERT(block_for_download.val < download->blocks_count);

  u64 block_offset = block_for_download.val * BLOCK_SIZE;
  u64 piece_offset_start = piece.val * download->piece_length;
  u64 piece_offset_end =
      piece_offset_start + download_compute_piece_length(download, piece);

  PG_ASSERT(piece_offset_end > piece_offset_start);
  PG_ASSERT(piece_offset_end - piece_offset_start <= download->piece_length);
  PG_ASSERT(piece_offset_start <= block_offset);
  PG_ASSERT(block_offset < piece_offset_end);

  u64 res = (block_offset - piece_offset_start) / BLOCK_SIZE;
  PG_ASSERT(res <= UINT32_MAX);
  PG_ASSERT(res < download->blocks_per_piece_max);
  PG_ASSERT(res < download_compute_blocks_count_for_piece(download, piece));

  return (BlockForPieceIndex){(u32)res};
}

[[maybe_unused]] [[nodiscard]] static PieceIndex
download_get_piece_for_block(Download *download,
                             BlockForDownloadIndex block_for_download) {
  PG_ASSERT(block_for_download.val < download->blocks_count);

  u32 res = block_for_download.val / download->blocks_per_piece_max;
  PG_ASSERT(res < download->pieces_count);

  return (PieceIndex){res};
}

[[maybe_unused]] [[nodiscard]] static u32 download_compute_block_length(
    Download *download, BlockForPieceIndex block_for_piece, PieceIndex piece) {
  PG_ASSERT(piece.val < download->pieces_count);
  PG_ASSERT(block_for_piece.val < download->blocks_per_piece_max);
  PG_ASSERT(block_for_piece.val * BLOCK_SIZE < download->piece_length);

  if (piece.val + 1 < download->pieces_count) { // General case.
    return BLOCK_SIZE;
  }

  u32 blocks_for_piece_count =
      download_compute_blocks_count_for_piece(download, piece);

  if (block_for_piece.val + 1 < blocks_for_piece_count) {
    return BLOCK_SIZE;
  }

  // Special case for the last block of the last piece.
  u32 res = (u32)(download_compute_piece_length(download, piece) -
                  (u64)block_for_piece.val * BLOCK_SIZE);
  PG_ASSERT(res > 0);
  PG_ASSERT(res <= BLOCK_SIZE);

  return res;
}

[[nodiscard]] static bool download_verify_piece_data(PgString data,
                                                     PgString hash_expected) {
  PG_ASSERT(PG_SHA1_DIGEST_LENGTH == hash_expected.len);

  PgSha1 hash_got = pg_sha1(data);
  return memcmp(hash_got.data, hash_expected.data, hash_expected.len) == 0;
}

[[maybe_unused]] [[nodiscard]] static PgFileDescriptorResult
download_file_create_if_not_exists(PgString path, u64 size,
                                   PgAllocator *allocator) {
  PgString filename = pg_path_base_name(path);
  PG_ASSERT(pg_string_eq(filename, path));

  PgFileDescriptorResult res = {0};

  // Open.
  PgFileDescriptor file = {0};
  {
    res = pg_file_open(filename, PG_FILE_ACCESS_READ_WRITE, true, allocator);
    if (res.err) {
      goto end;
    }
  }
  file = res.res;

  // Truncate.
  {
    PgError err_truncate = pg_file_truncate(file, size);
    if (err_truncate) {
      res.err = err_truncate;
      goto end;
    }
  }

end:
  if (res.err) {
    if (file.fd) {
      (void)pg_file_close(file);
    }
  }

  return res;
}

typedef struct {
  PgString info_hash;
  u32 piece_i;
  Download *download;
} DownloadLoadBitfieldFromDiskCtx;

[[maybe_unused]] [[nodiscard]] static PgError
download_file_on_chunk(PgString chunk, void *ctx) {
  DownloadLoadBitfieldFromDiskCtx *d = ctx;
  PG_ASSERT(d->piece_i < d->download->pieces_count);

  PgString sha_expected =
      PG_SLICE_RANGE(d->info_hash, PG_SHA1_DIGEST_LENGTH * d->piece_i,
                     PG_SHA1_DIGEST_LENGTH * (d->piece_i + 1));
  bool eq = download_verify_piece_data(chunk, sha_expected);

  pg_bitfield_set(d->download->pieces_have, d->piece_i, eq);
  d->download->pieces_have_count += eq;
  PG_ASSERT(d->download->pieces_have_count <= d->download->pieces_count);

  pg_log(d->download->logger, PG_LOG_LEVEL_DEBUG, "chunk",
         pg_log_cu64("len", chunk.len), pg_log_cu64("piece", d->piece_i),
         pg_log_cu32("pieces_count", d->download->pieces_count),
         pg_log_cu64("eq", (u64)eq),
         pg_log_cu64("pieces_have_count", d->download->pieces_have_count));

  d->piece_i += 1;

  return 0;
}

typedef PgError (*PgFileReadOnChunk)(PgString chunk, void *ctx);

// TODO: Async.
[[nodiscard]] [[maybe_unused]] static PgError
pg_file_read_chunks(PgFileDescriptor file, PgLogger *logger, u64 chunk_size,
                    PgFileReadOnChunk on_chunk, void *ctx, PgArena arena) {

  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  PgError err = 0;
  PgString buf = pg_string_make(4 * PG_MiB, allocator);
  PgRing ring = pg_ring_make(2 * buf.len, allocator);
  PgString chunk = pg_string_make(chunk_size, allocator);

  for (;;) {
    PgU64Result res_read = pg_file_read(file, buf);

    if (res_read.err) {
      pg_log(
          logger, PG_LOG_LEVEL_ERROR, "failed to read file",
          pg_log_ci32("err", (i32)res_read.err),
          pg_log_cs("err_msg", pg_cstr_to_string(strerror((i32)res_read.err))));
      err = res_read.err;
      goto end;
    }
    PgString buf_read = PG_SLICE_RANGE(buf, 0, res_read.res);
    pg_log(logger, PG_LOG_LEVEL_DEBUG, "file chunk read",
           pg_log_cu64("len", buf_read.len));

    PG_ASSERT(pg_ring_write_slice(&ring, buf_read));
    while (pg_ring_read_slice(&ring, chunk)) {
      err = on_chunk(chunk, ctx);
      if (err) {
        goto end;
      }
    }

    if (0 == buf_read.len) { // EOF.
      goto end;
    }
  }

end:
  // TODO: free stuff.

  return err;
}

[[maybe_unused]] [[nodiscard]] static PgStringResult
download_load_bitfield_pieces_from_disk(PgFileDescriptor file,
                                        Download *download, PgString path,
                                        PgString info_hash) {
  PG_ASSERT(download->pieces_have.len > 0);
  u64 start = pg_time_ns_now(PG_CLOCK_KIND_MONOTONIC).res;
  pg_log(download->logger, PG_LOG_LEVEL_INFO,
         "download_load_bitfield_pieces_from_disk start",
         pg_log_cs("path", path));

  DownloadLoadBitfieldFromDiskCtx ctx = {
      .info_hash = info_hash,
      .download = download,
  };

  PgStringResult res = {0};
  {
    PgArena arena = pg_arena_make_from_virtual_mem(16 * PG_MiB);
    PgError err =
        pg_file_read_chunks(file, download->logger, download->piece_length,
                            download_file_on_chunk, &ctx, arena);
    (void)pg_arena_release(&arena);

    if (err) {
      res.err = err;
      return res;
    }
  }

  u64 end = pg_time_ns_now(PG_CLOCK_KIND_MONOTONIC).res;
  pg_log(download->logger, PG_LOG_LEVEL_INFO,
         "download_load_bitfield_pieces_from_disk end", pg_log_cs("path", path),
         pg_log_cu64("duration_ms", pg_ns_to_ms(end - start)));
  return res;
}

[[maybe_unused]] [[nodiscard]] static BlockForDownloadIndexOk
download_pick_next_block(Download *download, PgString remote_pieces_have,
                         PieceDownloadDyn *downloading_pieces) {
  PG_ASSERT(download->concurrent_downloads_count <=
            download->cfg->download_max_concurrent_downloads);
  PG_ASSERT(pg_div_ceil(download->pieces_count, 8) == remote_pieces_have.len);
  PG_ASSERT(downloading_pieces->len <=
            download->cfg->download_max_concurrent_downloads);

  BlockForDownloadIndexOk res = {0};

  if (download->concurrent_downloads_count ==
      download->cfg->download_max_concurrent_downloads) {
    return res;
  }

  // Prefer downloading all blocks for one piece, to identify
  // bad peers.
  for (u64 i = 0; i < downloading_pieces->len; i++) {
    PieceDownload *piece_download = PG_SLICE_AT_PTR(downloading_pieces, i);
    PG_ASSERT(piece_download->piece.val < download->pieces_count);
    PG_ASSERT(pg_bitfield_get(remote_pieces_have, piece_download->piece.val));

    PG_ASSERT(false == pg_bitfield_get(download->pieces_have,
                                       piece_download->piece.val));
    PG_ASSERT(true == pg_bitfield_get(download->pieces_downloading,
                                      piece_download->piece.val));

    u32 blocks_count_for_piece = download_compute_blocks_count_for_piece(
        download, piece_download->piece);

    for (u32 j = 0; j < blocks_count_for_piece; j++) {
      BlockForPieceIndex block_for_piece = {j};
      BlockForDownloadIndex block_for_download =
          download_convert_block_for_piece_to_block_for_download(
              download, piece_download->piece, block_for_piece);
      if (pg_bitfield_get_ptr(
              piece_download->blocks_downloading,
              PG_STATIC_ARRAY_LEN(piece_download->blocks_downloading),
              block_for_piece.val)) {
        continue;
      }

      if (pg_bitfield_get_ptr(piece_download->blocks_have,
                              PG_STATIC_ARRAY_LEN(piece_download->blocks_have),
                              block_for_piece.val)) {
        continue;
      }

      PG_ASSERT(!pg_bitfield_get_ptr(
          piece_download->blocks_downloading,
          PG_STATIC_ARRAY_LEN(piece_download->blocks_downloading),
          block_for_piece.val));
      pg_bitfield_set_ptr(
          piece_download->blocks_downloading,
          PG_STATIC_ARRAY_LEN(piece_download->blocks_downloading),
          block_for_piece.val, true);

      pg_log(download->logger, PG_LOG_LEVEL_DEBUG,
             "download: picked next block for piece being downloaded",
             pg_log_cu64("piece", piece_download->piece.val),
             pg_log_cu64("block_for_piece", block_for_piece.val),
             pg_log_cu64("block_for_download", block_for_download.val),
             pg_log_cu64("piece_download_i", i));

      res.ok = true;
      res.res = block_for_download;
      return res;
    }
  }

  // Start downloading a new piece.
  u32 start =
      pg_rand_u32_min_incl_max_excl(download->rng, 0, download->pieces_count);
  for (u32 i = 0; i < download->pieces_count; i++) {
    PieceIndex piece = {(start + i) % download->pieces_count};
    if (pg_bitfield_get(download->pieces_have, piece.val)) {
      continue;
    }

    if (!pg_bitfield_get(remote_pieces_have, piece.val)) {
      continue;
    }

    if (pg_bitfield_get(download->pieces_downloading, piece.val)) {
      continue;
    }

    PG_ASSERT(false == pg_bitfield_get(download->pieces_have, piece.val));
    PG_ASSERT(false ==
              pg_bitfield_get(download->pieces_downloading, piece.val));
    *PG_DYN_PUSH_WITHIN_CAPACITY(downloading_pieces) =
        (PieceDownload){.piece = piece};
    pg_bitfield_set(download->pieces_downloading, piece.val, true);

    // Start at block 0 for simplicity.
    BlockForPieceIndex block_for_piece = {0};
    BlockForDownloadIndex block_for_download =
        download_convert_block_for_piece_to_block_for_download(download, piece,
                                                               block_for_piece);

    PieceDownload *piece_download = PG_SLICE_LAST_PTR(downloading_pieces);
    pg_bitfield_set_ptr(piece_download->blocks_downloading,
                        PG_STATIC_ARRAY_LEN(piece_download->blocks_downloading),
                        block_for_piece.val, true);

    pg_log(download->logger, PG_LOG_LEVEL_DEBUG,
           "download: picked next block for new piece being downloaded",
           pg_log_cu64("piece", piece_download->piece.val),
           pg_log_cu64("block_for_piece", block_for_piece.val),
           pg_log_cu64("block_for_download", block_for_download.val));
    res.res = block_for_download;
    res.ok = true;
    return res;
  }

  return res;
}

[[nodiscard]] static bool
download_verify_block_downloads(BlockDownload *block_downloads,
                                u64 block_downloads_len,
                                PgString hash_expected) {
  PG_ASSERT(PG_SHA1_DIGEST_LENGTH == hash_expected.len);

  PG_SHA1_CTX ctx = {0};
  PG_SHA1Init(&ctx);
  for (u64 i = 0; i < block_downloads_len; i++) {
    BlockDownload block_download =
        PG_C_ARRAY_AT(block_downloads, block_downloads_len, i);

    // Check that they are in order.
    if (i > 0) {
      PG_ASSERT(
          block_download.block.val >
          PG_C_ARRAY_AT(block_downloads, block_downloads_len, i - 1).block.val);
    }

    PG_SHA1Update(&ctx, block_download.data.data, block_download.data.len);
  }

  u8 hash[PG_SHA1_DIGEST_LENGTH] = {0};
  PG_SHA1Final(hash, &ctx);

  return 0 == memcmp(hash, hash_expected.data, hash_expected.len);
}

[[maybe_unused]] [[nodiscard]] static bool
download_verify_piece(Download *download, PieceDownload *pd) {
  PG_ASSERT(pd->piece.val < download->pieces_count);
  PG_ASSERT(pd->block_downloads_len ==
            download_compute_blocks_count_for_piece(download, pd->piece));
  PG_ASSERT(download->pieces_hash.len ==
            PG_SHA1_DIGEST_LENGTH * download->pieces_count);

  pg_log(download->logger, PG_LOG_LEVEL_DEBUG, "download: verifying piece",
         pg_log_ci32("file", download->file.fd),
         pg_log_cu64("piece", pd->piece.val));

  PgString hash_expected = PG_SLICE_RANGE(
      download->pieces_hash, PG_SHA1_DIGEST_LENGTH * pd->piece.val,
      PG_SHA1_DIGEST_LENGTH * (pd->piece.val + 1));

  // TODO: Custom sort (glibc's qsort allocates :/).
  qsort(pd->block_downloads, pd->block_downloads_len, sizeof(BlockDownload),
        block_downloads_sort);

  bool verified = download_verify_block_downloads(
      pd->block_downloads, pd->block_downloads_len, hash_expected);

  pg_log(download->logger, PG_LOG_LEVEL_DEBUG, "download: verified piece",
         pg_log_ci32("file", download->file.fd),
         pg_log_cu64("piece", pd->piece.val),
         pg_log_cu64("verified", (u64)verified));

  return verified;
}
