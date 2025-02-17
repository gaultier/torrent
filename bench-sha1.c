#include "sha1_sw.h"
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <immintrin.h>

typedef union {
  uint32_t u32[4];
  __m128i u128;
} v4si __attribute__((aligned(16)));

static const v4si K00_19 = {
    .u32 = {0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999}};
static const v4si K20_39 = {
    .u32 = {0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1}};
static const v4si K40_59 = {
    .u32 = {0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc}};
static const v4si K60_79 = {
    .u32 = {0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6}};

#define UNALIGNED 1
#if UNALIGNED
#define load(p) _mm_loadu_si128(p)
#else
#define load(p) (*p)
#endif

/*
        the first 16 bytes only need byte swapping

        prepared points to 4x uint32_t, 16-byte aligned

        W points to the 4 dwords which need preparing --
        and is overwritten with the swapped bytes
*/
#define prep00_15(prep, W)                                                     \
  do {                                                                         \
    __m128i r1, r2;                                                            \
                                                                               \
    r1 = (W);                                                                  \
    if (1) {                                                                   \
      r1 = _mm_shufflehi_epi16(r1, _MM_SHUFFLE(2, 3, 0, 1));                   \
      r1 = _mm_shufflelo_epi16(r1, _MM_SHUFFLE(2, 3, 0, 1));                   \
      r2 = _mm_slli_epi16(r1, 8);                                              \
      r1 = _mm_srli_epi16(r1, 8);                                              \
      r1 = _mm_or_si128(r1, r2);                                               \
      (W) = r1;                                                                \
    }                                                                          \
    (prep).u128 = _mm_add_epi32(K00_19.u128, r1);                              \
  } while (0)

/*
        for each multiple of 4, t, we want to calculate this:

        W[t+0] = rol(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
        W[t+1] = rol(W[t-2] ^ W[t-7] ^ W[t-13] ^ W[t-15], 1);
        W[t+2] = rol(W[t-1] ^ W[t-6] ^ W[t-12] ^ W[t-14], 1);
        W[t+3] = rol(W[t]   ^ W[t-5] ^ W[t-11] ^ W[t-13], 1);

        we'll actually calculate this:

        W[t+0] = rol(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
        W[t+1] = rol(W[t-2] ^ W[t-7] ^ W[t-13] ^ W[t-15], 1);
        W[t+2] = rol(W[t-1] ^ W[t-6] ^ W[t-12] ^ W[t-14], 1);
        W[t+3] = rol(  0    ^ W[t-5] ^ W[t-11] ^ W[t-13], 1);
        W[t+3] ^= rol(W[t+0], 1);

        the parameters are:

        W0 = &W[t-16];
        W1 = &W[t-12];
        W2 = &W[t- 8];
        W3 = &W[t- 4];

        and on output:
                prepared = W0 + K
                W0 = W[t]..W[t+3]
*/

/* note that there is a step here where i want to do a rol by 1, which
 * normally would look like this:
 *
 * r1 = psrld r0,$31
 * r0 = pslld r0,$1
 * r0 = por r0,r1
 *
 * but instead i do this:
 *
 * r1 = pcmpltd r0,zero
 * r0 = paddd r0,r0
 * r0 = psub r0,r1
 *
 * because pcmpltd and paddd are availabe in both MMX units on
 * efficeon, pentium-m, and opteron but shifts are available in
 * only one unit.
 */
#define prep(prep, XW0, XW1, XW2, XW3, K)                                      \
  do {                                                                         \
    __m128i r0, r1, r2, r3;                                                    \
                                                                               \
    /* load W[t-4] 16-byte aligned, and shift */                               \
    r3 = _mm_srli_si128((XW3), 4);                                             \
    r0 = (XW0);                                                                \
    /* get high 64-bits of XW0 into low 64-bits */                             \
    r1 = _mm_shuffle_epi32((XW0), _MM_SHUFFLE(1, 0, 3, 2));                    \
    /* load high 64-bits of r1 */                                              \
    r1 = _mm_unpacklo_epi64(r1, (XW1));                                        \
    r2 = (XW2);                                                                \
                                                                               \
    r0 = _mm_xor_si128(r1, r0);                                                \
    r2 = _mm_xor_si128(r3, r2);                                                \
    r0 = _mm_xor_si128(r2, r0);                                                \
    /* unrotated W[t]..W[t+2] in r0 ... still need W[t+3] */                   \
                                                                               \
    r2 = _mm_slli_si128(r0, 12);                                               \
    r1 = _mm_cmplt_epi32(r0, _mm_setzero_si128());                             \
    r0 = _mm_add_epi32(r0, r0); /* shift left by 1 */                          \
    r0 = _mm_sub_epi32(r0, r1); /* r0 has W[t]..W[t+2] */                      \
                                                                               \
    r3 = _mm_srli_epi32(r2, 30);                                               \
    r2 = _mm_slli_epi32(r2, 2);                                                \
                                                                               \
    r0 = _mm_xor_si128(r0, r3);                                                \
    r0 = _mm_xor_si128(r0, r2); /* r0 now has W[t+3] */                        \
                                                                               \
    (XW0) = r0;                                                                \
    (prep).u128 = _mm_add_epi32(r0, (K).u128);                                 \
  } while (0)

static inline uint32_t f00_19(uint32_t x, uint32_t y, uint32_t z) {
  /* FIPS 180-2 says this: (x & y) ^ (~x & z)
   * but we can calculate it in fewer steps.
   */
  return ((y ^ z) & x) ^ z;
}

static inline uint32_t f20_39(uint32_t x, uint32_t y, uint32_t z) {
  return (x ^ z) ^ y;
}

static inline uint32_t f40_59(uint32_t x, uint32_t y, uint32_t z) {
  /* FIPS 180-2 says this: (x & y) ^ (x & z) ^ (y & z)
   * but we can calculate it in fewer steps.
   */
  return (x & z) | ((x | z) & y);
}

static inline uint32_t f60_79(uint32_t x, uint32_t y, uint32_t z) {
  return f20_39(x, y, z);
}

#define step(nn_mm, xa, xb, xc, xd, xe, xt, input)                             \
  do {                                                                         \
    (xt) = (input) + f##nn_mm((xb), (xc), (xd));                               \
    (xb) = rol((xb), 30);                                                      \
    (xt) += ((xe) + rol((xa), 5));                                             \
  } while (0)

static void sha1_sse_step(uint32_t *restrict H, const uint32_t *restrict inputu,
                          size_t num_steps) {
  const __m128i *restrict input = (const __m128i *)inputu;
  __m128i W0, W1, W2, W3;
  v4si prep0, prep1, prep2;
  uint32_t a, b, c, d, e, t;

  a = H[0];
  b = H[1];
  c = H[2];
  d = H[3];
  e = H[4];

  /* i've tried arranging the SSE2 code to be 4, 8, 12, and 16
   * steps ahead of the integer code.  12 steps ahead seems
   * to produce the best performance. -dean
   */
  W0 = load(&input[0]);
  prep00_15(prep0, W0); /* prepare for 00 through 03 */
  W1 = load(&input[1]);
  prep00_15(prep1, W1); /* prepare for 04 through 07 */
  W2 = load(&input[2]);
  prep00_15(prep2, W2); /* prepare for 08 through 11 */
  for (;;) {
    W3 = load(&input[3]);
    step(00_19, a, b, c, d, e, t, prep0.u32[0]); /* 00 */
    step(00_19, t, a, b, c, d, e, prep0.u32[1]); /* 01 */
    step(00_19, e, t, a, b, c, d, prep0.u32[2]); /* 02 */
    step(00_19, d, e, t, a, b, c, prep0.u32[3]); /* 03 */
    prep00_15(prep0, W3);
    step(00_19, c, d, e, t, a, b, prep1.u32[0]); /* 04 */
    step(00_19, b, c, d, e, t, a, prep1.u32[1]); /* 05 */
    step(00_19, a, b, c, d, e, t, prep1.u32[2]); /* 06 */
    step(00_19, t, a, b, c, d, e, prep1.u32[3]); /* 07 */
    prep(prep1, W0, W1, W2, W3, K00_19);         /* prepare for 16 through 19 */
    step(00_19, e, t, a, b, c, d, prep2.u32[0]); /* 08 */
    step(00_19, d, e, t, a, b, c, prep2.u32[1]); /* 09 */
    step(00_19, c, d, e, t, a, b, prep2.u32[2]); /* 10 */
    step(00_19, b, c, d, e, t, a, prep2.u32[3]); /* 11 */
    prep(prep2, W1, W2, W3, W0, K20_39);         /* prepare for 20 through 23 */
    step(00_19, a, b, c, d, e, t, prep0.u32[0]); /* 12 */
    step(00_19, t, a, b, c, d, e, prep0.u32[1]); /* 13 */
    step(00_19, e, t, a, b, c, d, prep0.u32[2]); /* 14 */
    step(00_19, d, e, t, a, b, c, prep0.u32[3]); /* 15 */
    prep(prep0, W2, W3, W0, W1, K20_39);
    step(00_19, c, d, e, t, a, b, prep1.u32[0]); /* 16 */
    step(00_19, b, c, d, e, t, a, prep1.u32[1]); /* 17 */
    step(00_19, a, b, c, d, e, t, prep1.u32[2]); /* 18 */
    step(00_19, t, a, b, c, d, e, prep1.u32[3]); /* 19 */

    prep(prep1, W3, W0, W1, W2, K20_39);
    step(20_39, e, t, a, b, c, d, prep2.u32[0]); /* 20 */
    step(20_39, d, e, t, a, b, c, prep2.u32[1]); /* 21 */
    step(20_39, c, d, e, t, a, b, prep2.u32[2]); /* 22 */
    step(20_39, b, c, d, e, t, a, prep2.u32[3]); /* 23 */
    prep(prep2, W0, W1, W2, W3, K20_39);
    step(20_39, a, b, c, d, e, t, prep0.u32[0]); /* 24 */
    step(20_39, t, a, b, c, d, e, prep0.u32[1]); /* 25 */
    step(20_39, e, t, a, b, c, d, prep0.u32[2]); /* 26 */
    step(20_39, d, e, t, a, b, c, prep0.u32[3]); /* 27 */
    prep(prep0, W1, W2, W3, W0, K20_39);
    step(20_39, c, d, e, t, a, b, prep1.u32[0]); /* 28 */
    step(20_39, b, c, d, e, t, a, prep1.u32[1]); /* 29 */
    step(20_39, a, b, c, d, e, t, prep1.u32[2]); /* 30 */
    step(20_39, t, a, b, c, d, e, prep1.u32[3]); /* 31 */
    prep(prep1, W2, W3, W0, W1, K40_59);
    step(20_39, e, t, a, b, c, d, prep2.u32[0]); /* 32 */
    step(20_39, d, e, t, a, b, c, prep2.u32[1]); /* 33 */
    step(20_39, c, d, e, t, a, b, prep2.u32[2]); /* 34 */
    step(20_39, b, c, d, e, t, a, prep2.u32[3]); /* 35 */
    prep(prep2, W3, W0, W1, W2, K40_59);
    step(20_39, a, b, c, d, e, t, prep0.u32[0]); /* 36 */
    step(20_39, t, a, b, c, d, e, prep0.u32[1]); /* 37 */
    step(20_39, e, t, a, b, c, d, prep0.u32[2]); /* 38 */
    step(20_39, d, e, t, a, b, c, prep0.u32[3]); /* 39 */

    prep(prep0, W0, W1, W2, W3, K40_59);
    step(40_59, c, d, e, t, a, b, prep1.u32[0]); /* 40 */
    step(40_59, b, c, d, e, t, a, prep1.u32[1]); /* 41 */
    step(40_59, a, b, c, d, e, t, prep1.u32[2]); /* 42 */
    step(40_59, t, a, b, c, d, e, prep1.u32[3]); /* 43 */
    prep(prep1, W1, W2, W3, W0, K40_59);
    step(40_59, e, t, a, b, c, d, prep2.u32[0]); /* 44 */
    step(40_59, d, e, t, a, b, c, prep2.u32[1]); /* 45 */
    step(40_59, c, d, e, t, a, b, prep2.u32[2]); /* 46 */
    step(40_59, b, c, d, e, t, a, prep2.u32[3]); /* 47 */
    prep(prep2, W2, W3, W0, W1, K40_59);
    step(40_59, a, b, c, d, e, t, prep0.u32[0]); /* 48 */
    step(40_59, t, a, b, c, d, e, prep0.u32[1]); /* 49 */
    step(40_59, e, t, a, b, c, d, prep0.u32[2]); /* 50 */
    step(40_59, d, e, t, a, b, c, prep0.u32[3]); /* 51 */
    prep(prep0, W3, W0, W1, W2, K60_79);
    step(40_59, c, d, e, t, a, b, prep1.u32[0]); /* 52 */
    step(40_59, b, c, d, e, t, a, prep1.u32[1]); /* 53 */
    step(40_59, a, b, c, d, e, t, prep1.u32[2]); /* 54 */
    step(40_59, t, a, b, c, d, e, prep1.u32[3]); /* 55 */
    prep(prep1, W0, W1, W2, W3, K60_79);
    step(40_59, e, t, a, b, c, d, prep2.u32[0]); /* 56 */
    step(40_59, d, e, t, a, b, c, prep2.u32[1]); /* 57 */
    step(40_59, c, d, e, t, a, b, prep2.u32[2]); /* 58 */
    step(40_59, b, c, d, e, t, a, prep2.u32[3]); /* 59 */

    prep(prep2, W1, W2, W3, W0, K60_79);
    step(60_79, a, b, c, d, e, t, prep0.u32[0]); /* 60 */
    step(60_79, t, a, b, c, d, e, prep0.u32[1]); /* 61 */
    step(60_79, e, t, a, b, c, d, prep0.u32[2]); /* 62 */
    step(60_79, d, e, t, a, b, c, prep0.u32[3]); /* 63 */
    prep(prep0, W2, W3, W0, W1, K60_79);
    step(60_79, c, d, e, t, a, b, prep1.u32[0]); /* 64 */
    step(60_79, b, c, d, e, t, a, prep1.u32[1]); /* 65 */
    step(60_79, a, b, c, d, e, t, prep1.u32[2]); /* 66 */
    step(60_79, t, a, b, c, d, e, prep1.u32[3]); /* 67 */
    prep(prep1, W3, W0, W1, W2, K60_79);
    step(60_79, e, t, a, b, c, d, prep2.u32[0]); /* 68 */
    step(60_79, d, e, t, a, b, c, prep2.u32[1]); /* 69 */
    step(60_79, c, d, e, t, a, b, prep2.u32[2]); /* 70 */
    step(60_79, b, c, d, e, t, a, prep2.u32[3]); /* 71 */

    --num_steps;
    if (num_steps == 0)
      break;

    input += 4;
    W0 = load(&input[0]);
    prep00_15(prep2, W0); /* prepare for next 00 through 03 */
    W1 = load(&input[1]);
    step(60_79, a, b, c, d, e, t, prep0.u32[0]); /* 72 */
    step(60_79, t, a, b, c, d, e, prep0.u32[1]); /* 73 */
    step(60_79, e, t, a, b, c, d, prep0.u32[2]); /* 74 */
    step(60_79, d, e, t, a, b, c, prep0.u32[3]); /* 75 */
    prep0 = prep2;        /* top of loop expects this in prep0 */
    prep00_15(prep2, W1); /* prepare for next 04 through 07 */
    W2 = load(&input[2]);
    step(60_79, c, d, e, t, a, b, prep1.u32[0]); /* 76 */
    step(60_79, b, c, d, e, t, a, prep1.u32[1]); /* 77 */
    step(60_79, a, b, c, d, e, t, prep1.u32[2]); /* 78 */
    step(60_79, t, a, b, c, d, e, prep1.u32[3]); /* 79 */
    prep1 = prep2;        /* top of loop expects this in prep1 */
    prep00_15(prep2, W2); /* prepare for next 08 through 11 */
    /* e, t, a, b, c, d */
    H[0] += e;
    H[1] += t;
    H[2] += a;
    H[3] += b;
    H[4] += c;

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
  }
  /* no more input to prepare */
  step(60_79, a, b, c, d, e, t, prep0.u32[0]); /* 72 */
  step(60_79, t, a, b, c, d, e, prep0.u32[1]); /* 73 */
  step(60_79, e, t, a, b, c, d, prep0.u32[2]); /* 74 */
  step(60_79, d, e, t, a, b, c, prep0.u32[3]); /* 75 */
  /* no more input to prepare */
  step(60_79, c, d, e, t, a, b, prep1.u32[0]); /* 76 */
  step(60_79, b, c, d, e, t, a, prep1.u32[1]); /* 77 */
  step(60_79, a, b, c, d, e, t, prep1.u32[2]); /* 78 */
  step(60_79, t, a, b, c, d, e, prep1.u32[3]); /* 79 */
  /* e, t, a, b, c, d */
  H[0] += e;
  H[1] += t;
  H[2] += a;
  H[3] += b;
  H[4] += c;
}

// Process as many 64 bytes chunks as possible.
static void pg_sha1_process_x86(uint32_t state[5], const uint8_t data[],
                                uint32_t length) {
  __m128i ABCD, ABCD_SAVE, E0, E0_SAVE, E1;
  __m128i MSG0, MSG1, MSG2, MSG3;
  const __m128i MASK =
      // First u64 (upper bits of i128):
      // 0000_0000'0000_0001'0000_0010'0000_0011'0000_0100'0000_0101'0000_0110'0000_0111
      // Second u64 (lower bits of i128):
      // 0000_1000'0000_1001'0000_1010'0000_1011'0000_1100'0000_1101'0000_1110'0000_1111
      // As `i1u` (16 u8): `0..=15`.
      _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);

  /* Load initial values */
  ABCD = _mm_loadu_si128((const __m128i *)(void *)state);
  E0 = _mm_set_epi32((int)state[4], 0, 0, 0);

  // `0x1b` == `0b0001_1011`.
  // Will result in:
  // [31:0] == [127:96] (due to bits [1:0] being `11`).
  // [63:32] == [95:64] (due to bits [3:2] being `10`).
  // [95:64] == [63:32] (due to bits [5:4] being `01`).
  // [127:96] == [31:0] (due to bits [7:6] being `00`).
  // I.e.: Transform state to big-endian.
  ABCD = _mm_shuffle_epi32(ABCD, 0x1B);

  while (length >= 64) {
    /* Save current state  */
    ABCD_SAVE = ABCD;
    E0_SAVE = E0;

    /* Rounds 0-3 */
    // Load first 16 bytes of data in `MSG0`.
    MSG0 = _mm_loadu_si128((const __m128i *)(void *)(data + 0));

    // for each byte in src:
    //    Bit 7: \n
    //    1: Clear the corresponding byte in the destination. \n
    //    0: Copy the selected source byte to the corresponding byte in the
    //    destination. \n
    //    Bits [6:4] Reserved.  \n
    //    Bits [3:0] select the source byte to be copied.
    //    Since MASK is 0..=15, we copy MSG0
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

  // Process as many 4 bytes chunks as possible.
  uint64_t len_rounded_down = (chunk_len / 64) * 64;
  uint64_t rem = chunk_len % 64;
  uint64_t steps = len_rounded_down / 64;
  sha1_sse_step(ctx.state, chunk, steps);

  memcpy(ctx.buffer, chunk + len_rounded_down, rem);

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
