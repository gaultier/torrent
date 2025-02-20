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

__attribute((unused)) __attribute((warn_unused_result)) static int do_write(uv_stream_t *stream,
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

  PgFile file;
  PgLogger *logger;
  PgRng *rng;
  PgArena arena;

  Configuration *cfg;

  // Counters.
  u64 concurrent_downloads_count;
  u64 peers_active_count;

} Download;

__attribute((warn_unused_result)) static u32 download_compute_pieces_count(u64 piece_length,
                                                       u64 total_file_size) {
  u64 res = pg_div_ceil(total_file_size, piece_length);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

__attribute((warn_unused_result)) static u32
download_compute_max_blocks_per_piece_count(u64 piece_length) {
  u64 res = pg_div_ceil(piece_length, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

__attribute((warn_unused_result)) __attribute((unused)) static Download
download_make(PgLogger *logger, PgRng *rng, Configuration *cfg,
              u64 piece_length, u64 total_size, PgString pieces_hash,
              PgFile file /* TODO: multiple files */) {
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

__attribute((warn_unused_result)) static i32 block_downloads_sort(const void *va, const void *vb) {
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

__attribute((warn_unused_result)) static u32 download_compute_piece_length(Download *download,
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

__attribute((unused)) __attribute((warn_unused_result)) static u32
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

__attribute((unused)) __attribute((warn_unused_result)) static BlockForDownloadIndex
download_convert_block_for_piece_to_block_for_download(
    Download *download, PieceIndex piece, BlockForPieceIndex block_for_piece) {
  PG_ASSERT(piece.val < download->pieces_count);
  PG_ASSERT(block_for_piece.val < download->blocks_per_piece_max);

  u32 res = piece.val * download->blocks_per_piece_max + block_for_piece.val;
  PG_ASSERT(res < download->blocks_count);

  return (BlockForDownloadIndex){res};
}

__attribute((unused)) __attribute((warn_unused_result)) static BlockForPieceIndex
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

__attribute((unused)) __attribute((warn_unused_result)) static PieceIndex
download_get_piece_for_block(Download *download,
                             BlockForDownloadIndex block_for_download) {
  PG_ASSERT(block_for_download.val < download->blocks_count);

  u32 res = block_for_download.val / download->blocks_per_piece_max;
  PG_ASSERT(res < download->pieces_count);

  return (PieceIndex){res};
}

__attribute((unused)) __attribute((warn_unused_result)) static u32 download_compute_block_length(
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

__attribute((warn_unused_result)) static bool download_verify_piece_data(PgString data,
                                                     PgString hash_expected) {
  PG_ASSERT(PG_SHA1_DIGEST_LENGTH == hash_expected.len);

  PgSha1 hash_got = pg_sha1(data);
  return memcmp(hash_got.data, hash_expected.data, hash_expected.len) == 0;
}

__attribute((unused)) __attribute((warn_unused_result)) static PgFileResult
download_file_create_if_not_exists(PgString path, u64 size) {
  PgString filename = pg_string_to_filename(path);
  PG_ASSERT(pg_string_eq(filename, path));

  char filename_c[PG_PATH_MAX] = {0};
  PG_ASSERT(pg_cstr_mut_from_string(filename_c, filename));

  PgFileResult res = {0};

  uv_fs_t req = {0};

  // Open.
  {
    int flags = UV_FS_O_CREAT | UV_FS_O_RDWR;
    int err_open =
        uv_fs_open(uv_default_loop(), &req, filename_c, flags, 0600, NULL);
    if (err_open < 0) {
      res.err = (PgError)err_open;
      goto end;
    }
    res.res = err_open;
    PG_ASSERT(res.res > 0);
  }

  // Truncate.
  {
    int err_file =
        uv_fs_ftruncate(uv_default_loop(), &req, res.res, (i64)size, NULL);
    if (err_file < 0) {
      res.err = (PgError)err_file;
      goto end;
    }
  }

end:
  if (res.err) {
    if (res.res) {
      PG_ASSERT(0 == uv_fs_close(uv_default_loop(), &req, res.res, NULL));
    }
    uv_fs_req_cleanup(&req);
  }

  return res;
}

typedef struct {
  PgString info_hash;
  u32 piece_i;
  Download *download;
} DownloadLoadBitfieldFromDiskCtx;

__attribute((unused)) __attribute((warn_unused_result)) static PgError
download_file_on_chunk(PgString chunk, void *ctx) {
  (void)chunk;
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
         PG_L("len", chunk.len), PG_L("piece", d->piece_i),
         PG_L("pieces_count", d->download->pieces_count), PG_L("eq", (u64)eq),
         PG_L("pieces_have_count", d->download->pieces_have_count));

  d->piece_i += 1;

  return 0;
}

__attribute((unused)) __attribute((warn_unused_result)) static PgStringResult
download_load_bitfield_pieces_from_disk(Download *download, PgString path,
                                        PgString info_hash) {
  PG_ASSERT(download->pieces_have.len > 0);
  u64 start = pg_time_ns_now(PG_CLOCK_KIND_MONOTONIC).res;
  pg_log(download->logger, PG_LOG_LEVEL_ERROR,
         "download_load_bitfield_pieces_from_disk start", PG_L("path", path));

  PgString filename = pg_string_to_filename(path);
  PG_ASSERT(pg_string_eq(filename, path));

  DownloadLoadBitfieldFromDiskCtx ctx = {
      .info_hash = info_hash,
      .download = download,
  };

  PgStringResult res = {0};
  {
    // FIXME: Use libuv here.
    PgArena arena = pg_arena_make_from_virtual_mem(download->piece_length);
    PgError err = pg_file_read_chunks(filename, download->piece_length,
                                      download_file_on_chunk, &ctx, arena);
    (void)pg_arena_release(&arena);

    if (err) {
      res.err = err;
      return res;
    }
  }

  u64 end = pg_time_ns_now(PG_CLOCK_KIND_MONOTONIC).res;
  pg_log(download->logger, PG_LOG_LEVEL_ERROR,
         "download_load_bitfield_pieces_from_disk end", PG_L("path", path),
         PG_L("duration_ms", pg_ns_to_ms(end - start)));
  return res;
}

__attribute((unused)) __attribute((warn_unused_result)) static BlockForDownloadIndexOk
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
             PG_L("piece", piece_download->piece.val),
             PG_L("block_for_piece", block_for_piece.val),
             PG_L("block_for_download", block_for_download.val),
             PG_L("piece_download_i", i));

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
           PG_L("piece", piece_download->piece.val),
           PG_L("block_for_piece", block_for_piece.val),
           PG_L("block_for_download", block_for_download.val));
    res.res = block_for_download;
    res.ok = true;
    return res;
  }

  return res;
}

__attribute((warn_unused_result)) static bool
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

__attribute((unused)) __attribute((warn_unused_result)) static bool
download_verify_piece(Download *download, PieceDownload *pd) {
  PG_ASSERT(pd->piece.val < download->pieces_count);
  PG_ASSERT(pd->block_downloads_len ==
            download_compute_blocks_count_for_piece(download, pd->piece));
  PG_ASSERT(download->pieces_hash.len ==
            PG_SHA1_DIGEST_LENGTH * download->pieces_count);

  pg_log(download->logger, PG_LOG_LEVEL_DEBUG, "download: verifying piece",
         PG_L("file", download->file), PG_L("piece", pd->piece.val));

  PgString hash_expected = PG_SLICE_RANGE(
      download->pieces_hash, PG_SHA1_DIGEST_LENGTH * pd->piece.val,
      PG_SHA1_DIGEST_LENGTH * (pd->piece.val + 1));

  // TODO: Custom sort (glibc's qsort allocates :/).
  qsort(pd->block_downloads, pd->block_downloads_len, sizeof(BlockDownload),
        block_downloads_sort);

  bool verified = download_verify_block_downloads(
      pd->block_downloads, pd->block_downloads_len, hash_expected);

  pg_log(download->logger, PG_LOG_LEVEL_DEBUG, "download: verified piece",
         PG_L("file", download->file), PG_L("piece", pd->piece.val),
         PG_L("verified", (u64)verified));

  return verified;
}
