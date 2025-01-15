#pragma once
#include "peer.c"

// TODO: use.
[[maybe_unused]] [[nodiscard]] static bool
pg_bitfield_has_all_blocks_for_piece(PgString pg_bitfield_blocks, u32 blocks_per_piece,
                                  u32 pieces_count, u32 piece) {
  PG_ASSERT(piece < pieces_count);
  PG_ASSERT(pg_bitfield_blocks.len ==
         pieces_count * blocks_per_piece); // TODO: round up?

  u32 idx_first_block = piece * blocks_per_piece;
  u32 idx_last_block = idx_first_block + blocks_per_piece - 1;

  bool res = true;

  for (u64 i = idx_first_block; i < idx_last_block; i++) {
    res &= pg_bitfield_get(pg_bitfield_blocks, i);
  }

  return res;
}

// FIXME: randomness.
// Pick a random piece that the remote claimed they have.
// TODO: use.
[[maybe_unused]] [[nodiscard]] static i64
pg_bitfield_pick_random_piece(PgString pg_bitfield_remote_pieces, u32 pieces_count) {
  for (u64 i = 0; i < pieces_count; i++) {
    if (pg_bitfield_get(pg_bitfield_remote_pieces, i)) {
      return (i64)i;
    }
  }
  return -1;
}

// TODO: use.
[[maybe_unused]] [[nodiscard]] static bool
piece_verify_hash(PgString data, PgString hash_expected) {
  PG_ASSERT(20 == hash_expected.len);
  PG_ASSERT(0 == data.len % BLOCK_LENGTH);

  u8 hash_got[20] = {0};
  pg_sha1(data, hash_got);
  return memcmp(hash_got, hash_expected.data, hash_expected.len) == 0;
}
