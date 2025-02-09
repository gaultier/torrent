#pragma once
#include "submodules/cstd/lib.c"

#define BLOCK_SIZE (1UL << 14)

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

// TODO: Consider having two separate types for these two kinds of blocks.
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
                  (u64)block_for_piece.val * BLOCK_SIZE);
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

  PgFileFlags flags =
      PG_FILE_FLAGS_CREATE | PG_FILE_FLAGS_READ | PG_FILE_FLAGS_WRITE;
  PgFileResult res = pg_file_open(filename, flags);
  if (res.err) {
    return res;
  }

  res.err = pg_file_set_size(filename, size);
  if (res.err) {
    (void)pg_file_close(res.res);
    return res;
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

  pg_log(d->download->logger, PG_LOG_LEVEL_DEBUG, "chunk",
         PG_L("len", chunk.len), PG_L("piece", d->piece_i),
         PG_L("pieces_count", d->download->pieces_count), PG_L("eq", (u64)eq));

  pg_bitfield_set(d->download->pieces_have, d->piece_i, eq);
  d->download->pieces_have_count += 1;
  PG_ASSERT(d->download->pieces_have_count <= d->download->pieces_count);

  d->download->blocks_have_count += download_compute_blocks_count_for_piece(
      d->download, (PieceIndex){d->piece_i});
  PG_ASSERT(d->download->blocks_have_count <= d->download->blocks_count);

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

[[maybe_unused]] [[nodiscard]] static BlockForDownloadIndexOk
download_pick_next_block(Download *download, PgString remote_pieces_have) {
  BlockForDownloadIndexOk res = {0};
  PG_ASSERT(download->concurrent_downloads_count <=
            download->concurrent_downloads_max);
  PG_ASSERT(pg_div_ceil(download->pieces_count, 8) == remote_pieces_have.len);

  if (download->concurrent_downloads_count ==
      download->concurrent_downloads_max) {
    return res;
  }

  // TODO: Prefer downloading all blocks for one piece, to identify
  // bad peers.
  // Currently we download random blocks without attention to which piece and
  // peer they come from.

  u32 start =
      pg_rand_u32_min_incl_max_excl(download->rng, 0, download->blocks_count);
  for (u64 i = 0; i < download->blocks_count;) {
    BlockForDownloadIndex block_for_download = {(start + i) %
                                                download->blocks_count};
    PG_ASSERT(block_for_download.val < download->blocks_count);

    if (pg_bitfield_get(download->blocks_have, block_for_download.val)) {
      i += 1;
      continue;
    }
    PieceIndex piece =
        download_get_piece_for_block(download, block_for_download);
    if (!pg_bitfield_get(remote_pieces_have, piece.val)) {
      BlockForPieceIndex block_for_piece =
          download_convert_block_for_download_to_block_for_piece(
              download, piece, block_for_download);
      u32 blocks_count_for_piece =
          download_compute_blocks_count_for_piece(download, piece);
      PG_ASSERT(block_for_piece.val < blocks_count_for_piece);

      i += blocks_count_for_piece - block_for_piece.val;
      continue;
    }

    res.res = block_for_download;
    res.ok = true;
    return res;
  }

  return res;
}
