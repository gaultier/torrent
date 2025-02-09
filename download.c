#pragma once
#include "submodules/cstd/lib.c"

#define BLOCK_SIZE (1UL << 14)

typedef struct {
  PgString pieces_have;
  PgString blocks_have;
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

[[nodiscard]] static u32
download_compute_max_blocks_per_piece_count(u64 piece_length) {
  u64 res = pg_div_ceil(piece_length, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

// TODO: Consider having two separate types for these two kinds of blocks.
[[nodiscard]] static u32 download_compute_piece_length(Download *download,
                                                       u32 piece) {
  PG_ASSERT(piece < download->pieces_count);
  PG_ASSERT(download->pieces_count > 0);
  PG_ASSERT(download->piece_length <= UINT32_MAX);

  u64 res = (piece + 1) == download->pieces_count
                ? download->total_file_size - piece * download->piece_length
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
download_compute_blocks_count_for_piece(Download *download, u32 piece) {
  PG_ASSERT(piece * download->piece_length <= download->total_file_size);

  u32 pieces_count = download_compute_pieces_count(download->piece_length,
                                                   download->total_file_size);
  PG_ASSERT(pieces_count > 0);

  if (piece < pieces_count - 1) {
    return download_compute_max_blocks_per_piece_count(download->piece_length);
  }

  u64 rem = download->total_file_size - piece * download->piece_length;

  u64 res = pg_div_ceil(rem, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

// TODO: Consider having two separate types for these two kinds of blocks.
[[maybe_unused]] [[nodiscard]] static u32
download_convert_block_for_download_to_block_for_piece(Download *download,
                                                       u32 piece,
                                                       u32 block_for_download) {
  PG_ASSERT(piece < download->pieces_count);
  PG_ASSERT(block_for_download < download->blocks_count);

  u64 block_offset = block_for_download * BLOCK_SIZE;
  u64 piece_offset_start = piece * download->piece_length;
  u64 piece_offset_end =
      piece_offset_start + download_compute_piece_length(download, piece);

  PG_ASSERT(piece_offset_start <= block_offset);
  PG_ASSERT(block_offset < piece_offset_end);

  u64 res = (piece_offset_end - block_offset) / BLOCK_SIZE;
  PG_ASSERT(res <= UINT32_MAX);
  PG_ASSERT(res <= download_compute_blocks_count_for_piece(download, piece));

  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static u32
download_get_piece_for_block(Download *download, u32 block_for_download) {
  PG_ASSERT(block_for_download < download->blocks_count);

  u32 res = block_for_download / download->max_blocks_per_piece_count;
  PG_ASSERT(res < download->pieces_count);

  return res;
}

[[maybe_unused]] [[nodiscard]] static u32
download_compute_blocks_count(u64 total_file_size) {
  u64 res = pg_div_ceil(total_file_size, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static u32
download_compute_block_length(u32 block_for_piece, u64 piece_length) {
  PG_ASSERT(block_for_piece * BLOCK_SIZE < piece_length);
  u32 res =
      (u32)(piece_length - (u64)block_for_piece * BLOCK_SIZE) % BLOCK_SIZE;
  if (0 == res) {
    res = BLOCK_SIZE;
  }

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
  PgString bitfield;
  PgString info_hash;
  PgLogger *logger;
  u64 piece_i;
  u64 pieces_count;
} DownloadLoadBitfieldFromDiskCtx;

[[maybe_unused]] [[nodiscard]] static PgError
download_file_on_chunk(PgString chunk, void *ctx) {
  (void)chunk;
  DownloadLoadBitfieldFromDiskCtx *d = ctx;
  PG_ASSERT(d->piece_i < d->pieces_count);

  PgString sha_expected =
      PG_SLICE_RANGE(d->info_hash, PG_SHA1_DIGEST_LENGTH * d->piece_i,
                     PG_SHA1_DIGEST_LENGTH * (d->piece_i + 1));
  bool eq = download_verify_piece_hash(chunk, sha_expected);

  pg_log(d->logger, PG_LOG_LEVEL_DEBUG, "chunk", PG_L("len", chunk.len),
         PG_L("piece", d->piece_i), PG_L("pieces_count", d->pieces_count),
         PG_L("eq", (u64)eq));

  pg_bitfield_set(d->bitfield, d->piece_i, eq);

  d->piece_i += 1;

  return 0;
}

[[maybe_unused]] [[nodiscard]] static PgStringResult
download_load_bitfield_pieces_from_disk(PgString path, PgString info_hash,
                                        u64 piece_length, u64 pieces_count,
                                        PgLogger *logger, PgArena *arena) {
  PgString filename = pg_string_to_filename(path);
  PG_ASSERT(pg_string_eq(filename, path));

  PgArenaAllocator arena_allocator = pg_make_arena_allocator(arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  DownloadLoadBitfieldFromDiskCtx ctx = {
      .bitfield = pg_string_make(pg_div_ceil(pieces_count, 8), allocator),
      .info_hash = info_hash,
      .logger = logger,
      .pieces_count = pieces_count,
  };

  PgStringResult res = {0};
  {
    PgArena arena_tmp = *arena;
    PgError err = pg_file_read_chunks(filename, piece_length,
                                      download_file_on_chunk, &ctx, arena_tmp);
    if (err) {
      res.err = err;
      return res;
    }
    res.res = ctx.bitfield;
  }

  return res;
}

[[maybe_unused]] [[nodiscard]] static Pgu32Ok
download_pick_next_block(Download *download, PgString remote_pieces_have) {
  Pgu32Ok res = {0};
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
    u32 block_for_download = (start + i) % download->blocks_count;
    if (pg_bitfield_get(download->blocks_have, block_for_download)) {
      i += 1;
      continue;
    }
    u32 piece = download_get_piece_for_block(download, block_for_download);
    if (!pg_bitfield_get(remote_pieces_have, piece)) {
      u32 block_for_piece =
          download_convert_block_for_download_to_block_for_piece(
              download, piece, block_for_download);
      u32 blocks_count_for_piece =
          download_compute_blocks_count_for_piece(download, piece);
      PG_ASSERT(block_for_piece < blocks_count_for_piece);

      i += blocks_count_for_piece - block_for_piece;
      continue;
    }

    res.res = block_for_download;
    res.ok = true;
    return res;
  }

  return res;
}
