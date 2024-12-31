#pragma once
#include "peer.c"

// TODO: use.
[[maybe_unused]] [[nodiscard]] static bool
bitfield_has_all_blocks_for_piece(String bitfield_blocks, u32 blocks_per_piece,
                                  u32 pieces_count, u32 piece) {
  ASSERT(piece < pieces_count);
  ASSERT(bitfield_blocks.len ==
         pieces_count * blocks_per_piece); // TODO: round up?

  u32 idx_first_block = piece * blocks_per_piece;
  u32 idx_last_block = idx_first_block + blocks_per_piece - 1;

  bool res = true;

  for (u64 i = idx_first_block; i < idx_last_block; i++) {
    res &= bitfield_get(bitfield_blocks, i);
  }

  return res;
}

// FIXME: randomness.
// Pick a random piece that the remote claimed they have.
// TODO: use.
[[maybe_unused]] [[nodiscard]] static i64
bitfield_pick_random_piece(String bitfield_remote_pieces, u32 pieces_count) {
  for (u64 i = 0; i < pieces_count; i++) {
    if (bitfield_get(bitfield_remote_pieces, i)) {
      return (i64)i;
    }
  }
  return -1;
}

// TODO: use.
[[maybe_unused]] [[nodiscard]] static bool
piece_verify_hash(String data, String hash_expected) {
  ASSERT(20 == hash_expected.len);
  ASSERT(0 == data.len % BLOCK_LENGTH);

  u8 hash_got[20] = {0};
  sha1(data, hash_got);
  return memcmp(hash_got, hash_expected.data, hash_expected.len) == 0;
}
