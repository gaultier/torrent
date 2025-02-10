#pragma once
#include "submodules/cstd/lib.c"

#include "submodules/libuv/include/uv.h"

#define BLOCK_SIZE (1UL << 14)

typedef struct {
  uv_write_t req;
  uv_buf_t buf;
  void *data;
} WriteRequest;

typedef struct {
  uv_fs_t req;
  uv_buf_t buf;
  void *data;
} FsWriteRequest;

[[nodiscard]] [[maybe_unused]]
static PgString uv_buf_to_string(uv_buf_t buf) {
  return (PgString){.data = (u8 *)buf.base, .len = buf.len};
}

[[nodiscard]]
static uv_buf_t string_to_uv_buf(PgString s) {
  return (uv_buf_t){.base = (char *)s.data, .len = s.len};
}

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

PG_DYN(PieceIndex) PieceIndexDyn;
PG_SLICE(PieceIndex) PieceIndexSlice;

typedef struct {
  u32 val;
} BlockForPieceIndex;

typedef struct {
  u32 val;
} BlockForDownloadIndex;

PG_OK(BlockForDownloadIndex) BlockForDownloadIndexOk;

typedef struct {
  PgString pieces_have;
  u32 pieces_have_count;

  PgString blocks_have;
  u32 blocks_have_count;

  u32 pieces_count;
  u32 blocks_count;
  u32 max_blocks_per_piece_count;
  u64 piece_length;
  u64 total_file_size;
  // TODO: Multiple files.
  PgFile file;
  PgLogger *logger;
  PgRng *rng;

  u64 concurrent_downloads_count;
  u64 concurrent_downloads_max;

  // All hashes (20 bytes long) for pieces, in one big string.
  PgString pieces_hash;
} Download;

[[maybe_unused]] [[nodiscard]] static u32
download_compute_max_blocks_per_piece_count(u64 piece_length) {
  u64 res = pg_div_ceil(piece_length, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

// TODO: Consider having two separate types for these two kinds of blocks.
[[nodiscard]] static u32 download_compute_piece_length(Download *download,
                                                       PieceIndex piece) {
  PG_ASSERT(piece.val < download->pieces_count);
  PG_ASSERT(download->pieces_count > 0);
  PG_ASSERT(download->piece_length <= UINT32_MAX);

  u64 res = (piece.val + 1) == download->pieces_count
                ? download->total_file_size - piece.val * download->piece_length
                : download->piece_length;

  PG_ASSERT(res <= UINT32_MAX);
  PG_ASSERT(res <= download->piece_length);

  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static u32
download_compute_pieces_count(u64 piece_length, u64 total_file_size) {
  u64 res = pg_div_ceil(total_file_size, piece_length);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static u32
download_compute_blocks_count_for_piece(Download *download, PieceIndex piece) {
  PG_ASSERT(piece.val * download->piece_length <= download->total_file_size);

  u32 pieces_count = download_compute_pieces_count(download->piece_length,
                                                   download->total_file_size);
  PG_ASSERT(pieces_count > 0);

  if (piece.val < pieces_count - 1) {
    PG_ASSERT(download->max_blocks_per_piece_count > 0);
    return download->max_blocks_per_piece_count;
  }

  u64 rem = download->total_file_size - piece.val * download->piece_length;

  u64 res = pg_div_ceil(rem, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  PG_ASSERT(res <= download->max_blocks_per_piece_count);
  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static BlockForDownloadIndex
download_convert_block_for_piece_to_block_for_download(
    Download *download, PieceIndex piece, BlockForPieceIndex block_for_piece) {
  PG_ASSERT(piece.val < download->pieces_count);
  PG_ASSERT(block_for_piece.val < download->max_blocks_per_piece_count);

  u32 res =
      piece.val * download->max_blocks_per_piece_count + block_for_piece.val;
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
  PG_ASSERT(res < download->max_blocks_per_piece_count);
  PG_ASSERT(res < download_compute_blocks_count_for_piece(download, piece));

  return (BlockForPieceIndex){(u32)res};
}

[[maybe_unused]] [[nodiscard]] static PieceIndex
download_get_piece_for_block(Download *download,
                             BlockForDownloadIndex block_for_download) {
  PG_ASSERT(block_for_download.val < download->blocks_count);

  u32 res = block_for_download.val / download->max_blocks_per_piece_count;
  PG_ASSERT(res < download->pieces_count);

  return (PieceIndex){res};
}

[[maybe_unused]] [[nodiscard]] static u32
download_compute_blocks_count(u64 total_file_size) {
  u64 res = pg_div_ceil(total_file_size, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static u32 download_compute_block_length(
    Download *download, BlockForPieceIndex block_for_piece, PieceIndex piece) {
  PG_ASSERT(piece.val < download->pieces_count);
  PG_ASSERT(block_for_piece.val < download->max_blocks_per_piece_count);
  PG_ASSERT(block_for_piece.val * BLOCK_SIZE < download->piece_length);

  if (piece.val + 1 < download->pieces_count) { // General case.
    return BLOCK_SIZE;
  }

  // Special case for the last piece.
  u32 res = (u32)(download_compute_piece_length(download, piece) -
                  (u64)block_for_piece.val * BLOCK_SIZE) %
            BLOCK_SIZE;
  PG_ASSERT(res > 0);
  PG_ASSERT(res <= BLOCK_SIZE);

  return res;
}

[[nodiscard]] static bool download_verify_piece_hash(PgString data,
                                                     PgString hash_expected) {
  PG_ASSERT(PG_SHA1_DIGEST_LENGTH == hash_expected.len);

  u8 hash_got[PG_SHA1_DIGEST_LENGTH] = {0};
  pg_sha1(data, hash_got);
  return memcmp(hash_got, hash_expected.data, hash_expected.len) == 0;
}

[[maybe_unused]] [[nodiscard]] static PgFileResult
download_file_create_if_not_exists(PgString path, u64 size) {
  PgString filename = pg_string_to_filename(path);
  PG_ASSERT(pg_string_eq(filename, path));

  char filename_c[PG_PATH_MAX] = {0};
  PG_ASSERT(pg_cstr_mut_from_string(filename_c, filename));

  PgFileResult res = {0};

  uv_fs_t req = {0};

  // Open.
  {
    int flags = O_CREAT | O_RDWR;
    int err_open =
        uv_fs_open(uv_default_loop(), &req, filename_c, flags, 0600, nullptr);
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
        uv_fs_ftruncate(uv_default_loop(), &req, res.res, (i64)size, nullptr);
    if (err_file < 0) {
      res.err = (PgError)err_file;
      goto end;
    }
  }

end:
  if (res.err) {
    if (res.res) {
      PG_ASSERT(0 == uv_fs_close(uv_default_loop(), &req, res.res, nullptr));
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

[[maybe_unused]] [[nodiscard]] static PgError
download_file_on_chunk(PgString chunk, void *ctx) {
  (void)chunk;
  DownloadLoadBitfieldFromDiskCtx *d = ctx;
  PG_ASSERT(d->piece_i < d->download->pieces_count);

  PgString sha_expected =
      PG_SLICE_RANGE(d->info_hash, PG_SHA1_DIGEST_LENGTH * d->piece_i,
                     PG_SHA1_DIGEST_LENGTH * (d->piece_i + 1));
  bool eq = download_verify_piece_hash(chunk, sha_expected);

  pg_bitfield_set(d->download->pieces_have, d->piece_i, eq);
  d->download->pieces_have_count += eq;
  PG_ASSERT(d->download->pieces_have_count <= d->download->pieces_count);

  d->download->blocks_have_count +=
      eq * download_compute_blocks_count_for_piece(d->download,
                                                   (PieceIndex){d->piece_i});
  PG_ASSERT(d->download->blocks_have_count <= d->download->blocks_count);

  pg_log(d->download->logger, PG_LOG_LEVEL_DEBUG, "chunk",
         PG_L("len", chunk.len), PG_L("piece", d->piece_i),
         PG_L("pieces_count", d->download->pieces_count), PG_L("eq", (u64)eq),
         PG_L("pieces_have_count", d->download->pieces_have_count));

  d->piece_i += 1;

  return 0;
}

[[maybe_unused]] [[nodiscard]] static PgStringResult
download_load_bitfield_pieces_from_disk(Download *download, PgString path,
                                        PgString info_hash) {
  PG_ASSERT(download->pieces_have.len > 0);

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

  return res;
}

[[nodiscard]] [[maybe_unused]] bool static download_has_all_blocks_for_piece(
    Download *download, PieceIndex piece) {
  PG_ASSERT(piece.val < download->pieces_count);

  BlockForDownloadIndex block_for_download = {
      piece.val * download->max_blocks_per_piece_count};
  u32 blocks_for_piece_count =
      download_compute_blocks_count_for_piece(download, piece);

  bool res = true;
  for (u32 i = 0; i < blocks_for_piece_count; i++) {
    u32 idx = block_for_download.val + i;
    res &= pg_bitfield_get(download->blocks_have, idx);
  }
  return res;
}

[[maybe_unused]] [[nodiscard]] static BlockForDownloadIndexOk
download_pick_next_block(Download *download, PgString remote_pieces_have,
                         PieceIndexDyn *downloading_pieces) {
  PG_ASSERT(download->concurrent_downloads_count <=
            download->concurrent_downloads_max);
  PG_ASSERT(pg_div_ceil(download->pieces_count, 8) == remote_pieces_have.len);
  PG_ASSERT(downloading_pieces->len <= download->concurrent_downloads_max);

  BlockForDownloadIndexOk res = {0};

  if (download->concurrent_downloads_count ==
      download->concurrent_downloads_max) {
    return res;
  }

  // Prefer downloading all blocks for one piece, to identify
  // bad peers.
  for (u64 i = 0; i < downloading_pieces->len; i++) {
    PieceIndex piece = PG_SLICE_AT(*downloading_pieces, i);
    PG_ASSERT(piece.val < download->pieces_count);

    PG_ASSERT(false == pg_bitfield_get(download->pieces_have, piece.val));

    u32 blocks_count_for_piece =
        download_compute_blocks_count_for_piece(download, piece);

    for (u32 j = 0; j < blocks_count_for_piece; j++) {
      BlockForPieceIndex block_for_piece = {j};
      BlockForDownloadIndex block_for_download =
          download_convert_block_for_piece_to_block_for_download(
              download, piece, block_for_piece);
      if (!pg_bitfield_get(download->blocks_have, block_for_download.val)) {
        res.ok = true;
        res.res = block_for_download;
        return res;
      }
    }
    PG_ASSERT(0 && "unreachable");
  }

  PG_ASSERT(0 == downloading_pieces->len);

  u32 start =
      pg_rand_u32_min_incl_max_excl(download->rng, 0, download->pieces_count);
  for (u32 i = 0; i < download->pieces_count; i++) {
    PieceIndex piece = {start + i % download->pieces_count};
    if (pg_bitfield_get(download->pieces_have, piece.val)) {
      continue;
    }

    if (!pg_bitfield_get(remote_pieces_have, piece.val)) {
      continue;
    }

    PG_ASSERT(false == pg_bitfield_get(download->pieces_have, piece.val));
    *PG_DYN_PUSH_WITHIN_CAPACITY(downloading_pieces) = piece;

    // Start at block 0 for simplicity.
    BlockForDownloadIndex block_for_download = {
        (u32)(piece.val * download->piece_length)};
    res.res = block_for_download;
    res.ok = true;
    return res;
  }

  return res;
}

[[maybe_unused]] [[nodiscard]] static PgError
download_verify_piece(Download *download, PieceIndex piece,
                      PgAllocator *allocator) {
  PG_ASSERT(piece.val < download->pieces_count);
  PG_ASSERT(download->pieces_hash.len ==
            PG_SHA1_DIGEST_LENGTH * download->pieces_count);

  pg_log(download->logger, PG_LOG_LEVEL_DEBUG, "download: verifying piece",
         PG_L("file", download->file), PG_L("piece", piece.val));

  PgString hash_expected =
      PG_SLICE_RANGE(download->pieces_hash, PG_SHA1_DIGEST_LENGTH * piece.val,
                     PG_SHA1_DIGEST_LENGTH * (piece.val + 1));

  u32 piece_length = download_compute_piece_length(download, piece);

  FsWriteRequest req = {0};
  req.req.data = &req;
  req.data = download;
  req.buf = string_to_uv_buf(pg_string_make(piece_length, allocator));

  u64 offset = (piece.val * download->piece_length);
  PG_ASSERT(offset <= download->total_file_size);
  PG_ASSERT(offset + piece_length <= download->total_file_size);

  int err_file =
      uv_fs_read(uv_default_loop(), &req.req, download->file, &req.buf, 1,
                 (i64)offset, nullptr /* TODO: Should it be async? */);
  if (err_file) {
    pg_log(download->logger, PG_LOG_LEVEL_ERROR,
           "download: failed to read block from disk",
           PG_L("file", download->file), PG_L("err", err_file),
           PG_L("err_msg", pg_cstr_to_string((char *)uv_strerror(err_file))));
    uv_fs_req_cleanup(&req.req);
    pg_free(allocator, req.buf.base, sizeof(u8), req.buf.len);
    return (PgError)err_file;
  }
  pg_log(download->logger, PG_LOG_LEVEL_DEBUG,
         "download: reading block from disk", PG_L("file", download->file));

  PgError err_verify =
      download_verify_piece_hash(uv_buf_to_string(req.buf), hash_expected);

  pg_free(allocator, req.buf.base, sizeof(u8), req.buf.len);
  uv_fs_req_cleanup(&req.req);

  pg_log(download->logger, PG_LOG_LEVEL_DEBUG, "download: verified piece",
         PG_L("file", download->file), PG_L("piece", piece.val),
         PG_L("err", err_verify));

  return err_verify;
}
