#include "sha1_sw.h"
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <immintrin.h>
// Process as many 64 bytes chunks as possible.
static void pg_sha1_process_x86(uint32_t state[5], const uint8_t data[],
                                uint32_t length) {
  __m128i ABCD, ABCD_SAVE, E0, E0_SAVE, E1;
  __m128i MSG0, MSG1, MSG2, MSG3;
  const __m128i MASK =
      // First u64:
      // 0000_0000'0000_0001'0000_0010'0000_0011'0000_0100'0000_0101'0000_0110'0000_0111
      // Second u64:
      // 0000_1000'0000_1001'0000_1010'0000_1011'0000_1100'0000_1101'0000_1110'0000_1111
      _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);

  /* Load initial values */
  ABCD = _mm_loadu_si128((const __m128i *)(void *)state);
  E0 = _mm_set_epi32((int)state[4], 0, 0, 0);
  ABCD = _mm_shuffle_epi32(ABCD, 0x1B);

  while (length >= 64) {
    /* Save current state  */
    ABCD_SAVE = ABCD;
    E0_SAVE = E0;

    /* Rounds 0-3 */
    MSG0 = _mm_loadu_si128((const __m128i *)(void *)(data + 0));
    MSG0 = _mm_shuffle_epi8(MSG0, MASK);
    E0 = _mm_add_epi32(E0, MSG0);
    E1 = ABCD;
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 0);

    /* Rounds 4-7 */
    MSG1 = _mm_loadu_si128((const __m128i *)(void *)(data + 16));
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG2 = _mm_loadu_si128((const __m128i *)(void *)(data + 32));
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 12-15 */
    MSG3 = _mm_loadu_si128((const __m128i *)(void *)(data + 48));
    MSG3 = _mm_shuffle_epi8(MSG3, MASK);
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 16-19 */
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 20-23 */
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 24-27 */
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 28-31 */
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 32-35 */
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 36-39 */
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 40-43 */
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 44-47 */
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 48-51 */
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 52-55 */
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 56-59 */
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 60-63 */
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 64-67 */
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 3);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 68-71 */
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 72-75 */
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E0, 3);

    /* Rounds 76-79 */
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    ABCD = (__m128i)_mm_sha1rnds4_epu32(ABCD, E1, 3);

    /* Combine state */
    E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

    data += 64;
    length -= 64;
  }

  /* Save state */
  ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
  _mm_storeu_si128((__m128i *)(void *)state, ABCD);
  state[4] = (uint32_t)_mm_extract_epi32(E0, 3);
}

static bool is_chunk_valid(uint8_t *chunk, uint64_t chunk_len,
                           uint8_t digest_expected[20]) {
  SHA1_CTX ctx = {0};
  SHA1Init(&ctx);

  // Process as many 64 bytes chunks as possible.
  pg_sha1_process_x86(ctx.state, chunk, (uint32_t)chunk_len);

  uint64_t len_rounded_down_64 = (chunk_len / 64) * 64;
  uint64_t rem = chunk_len % 64;
  memcpy(ctx.buffer, chunk + len_rounded_down_64, rem);

  ctx.count = chunk_len * 8;

  uint8_t digest_actual[20] = {0};
  SHA1Final(digest_actual, &ctx);

  return !memcmp(digest_actual, digest_expected, 20);
}

int main(int argc, char *argv[]) {
  if (3 != argc) {
    return 1;
  }

  int file_download = open(argv[1], O_RDONLY, 0600);
  if (!file_download) {
    return 1;
  }

  struct stat st_download = {0};
  if (-1 == fstat(file_download, &st_download)) {
    return 1;
  }
  size_t file_download_size = (size_t)st_download.st_size;

  uint8_t *file_download_data = mmap(NULL, file_download_size, PROT_READ,
                                     MAP_FILE | MAP_PRIVATE, file_download, 0);
  if (!file_download_data) {
    return 1;
  }

  int file_torrent = open(argv[2], O_RDONLY, 0600);
  if (!file_torrent) {
    return 1;
  }

  struct stat st_torrent = {0};
  if (-1 == fstat(file_torrent, &st_torrent)) {
    return 1;
  }
  size_t file_torrent_size = (size_t)st_torrent.st_size;

  uint8_t *file_torrent_data = mmap(NULL, file_torrent_size, PROT_READ,
                                    MAP_FILE | MAP_PRIVATE, file_torrent, 0);
  if (!file_torrent_data) {
    return 1;
  }
  // HACK
  uint64_t file_torrent_data_offset = 237;
  file_torrent_data += file_torrent_data_offset;
  file_torrent_size -= file_torrent_data_offset - 1;

  uint64_t piece_length = 262144;
  uint64_t pieces_count = file_download_size / piece_length +
                          ((0 == file_download_size % piece_length) ? 0 : 1);
  for (uint64_t i = 0; i < pieces_count; i++) {
    uint8_t *data = file_download_data + i * piece_length;
    uint64_t piece_length_real = ((i + 1) == pieces_count)
                                     ? (file_download_size - i * piece_length)
                                     : piece_length;
    uint8_t *digest_expected = file_torrent_data + i * 20;

    if (!is_chunk_valid(data, piece_length_real, digest_expected)) {
      return 1;
    }
  }
}
