#pragma once
#include "submodules/cstd/lib.c"

#define BLOCK_SIZE (1UL << 14)

typedef struct {
  PgString local_bitfield_have;
  u32 pieces_count;
  u32 blocks_per_piece_count;
  u64 piece_length;
  u64 total_file_size;
} Download;

[[maybe_unused]] [[nodiscard]] static bool
download_is_piece_length_valid(u64 piece_length) {
  if (0 == piece_length) {
    return false;
  }

  return true;
}

[[maybe_unused]] [[nodiscard]] static u32
download_compute_blocks_per_piece_count(u64 piece_length) {
  u64 res = pg_div_ceil(piece_length, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static u32
download_compute_pieces_count(u64 piece_length, u64 total_file_size) {
  u64 res = pg_div_ceil(total_file_size, piece_length);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

[[maybe_unused]] [[nodiscard]] static u32
download_compute_blocks_count_for_piece(u32 piece, u64 piece_length,
                                        u64 total_file_size) {
  u32 pieces_count =
      download_compute_pieces_count(piece_length, total_file_size);
  PG_ASSERT(pieces_count > 0);

  if (piece < pieces_count - 1) {
    return download_compute_blocks_per_piece_count(piece_length);
  }

  PG_ASSERT(piece * piece_length <= total_file_size);

  u64 rem = total_file_size - piece * piece_length;

  u64 res = pg_div_ceil(rem, BLOCK_SIZE);
  PG_ASSERT(res <= UINT32_MAX);
  return (u32)res;
}

// TODO: use.
[[maybe_unused]] [[nodiscard]] static bool
download_has_all_blocks_for_piece(PgString bitfield_blocks,
                                  u32 blocks_per_piece, u32 pieces_count,
                                  u32 piece) {
  PG_ASSERT(piece < pieces_count);
  PG_ASSERT(bitfield_blocks.len ==
            pieces_count * blocks_per_piece); // TODO: round up?

  u32 idx_first_block = piece * blocks_per_piece;
  u32 idx_last_block = idx_first_block + blocks_per_piece - 1;

  bool res = true;

  for (u64 i = idx_first_block; i < idx_last_block; i++) {
    res &= pg_bitfield_get(bitfield_blocks, i);
  }

  return res;
}

// Pick a random piece that the remote claimed they have.
[[maybe_unused]] [[nodiscard]] static i32
download_pick_next_piece(Download *download, PgString remote_bitfield_have) {
  PG_ASSERT(download->local_bitfield_have.len == remote_bitfield_have.len);

  u64 start = pg_rand_u32(0, download->pieces_count);
  for (u64 i = 0; i < download->pieces_count; i++) {
    u64 idx = (start + i) % download->pieces_count;
    if (!pg_bitfield_get(download->local_bitfield_have, idx) &&
        pg_bitfield_get(remote_bitfield_have, idx)) {

      PG_ASSERT(idx <= UINT32_MAX);
      return (i32)idx;
    }
  }
  return -1;
}

// TODO: use.
[[maybe_unused]] [[nodiscard]] static bool
download_verify_piece_hash(PgString data, PgString hash_expected) {
  PG_ASSERT(20 == hash_expected.len);

  u8 hash_got[20] = {0};
  pg_sha1(data, hash_got);
  return memcmp(hash_got, hash_expected.data, hash_expected.len) == 0;
}

[[maybe_unused]] [[nodiscard]] static PgError
download_file_create_if_not_exists(PgString path, u64 size, PgArena arena) {
  PgString filename = pg_string_to_filename(path);
  PG_ASSERT(pg_string_eq(filename, path));

  PgFileFlags flags =
      PG_FILE_FLAGS_CREATE | PG_FILE_FLAGS_READ | PG_FILE_FLAGS_WRITE;
  PgError err = pg_file_create(filename, flags, arena);
  if (err) {
    return err;
  }

  err = pg_file_set_size(filename, size, arena);
  if (err) {
    return err;
  }

  return 0;
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
      PG_SLICE_RANGE(d->info_hash, 20 * d->piece_i, 20 * (d->piece_i + 1));
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

  DownloadLoadBitfieldFromDiskCtx ctx = {
      .bitfield = pg_string_make(pg_div_ceil(pieces_count, 8), arena),
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
