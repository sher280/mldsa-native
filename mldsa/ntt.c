/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ntt.h"
#include <stdint.h>
#include "params.h"
#include "reduce.h"

static int32_t mld_fqmul(int32_t a, int32_t b)
__contract__(
  requires(b > -MLDSA_Q_HALF && b < MLDSA_Q_HALF)
  ensures(return_value > -MLDSA_Q && return_value < MLDSA_Q)
)
{
  return montgomery_reduce((int64_t)a * (int64_t)b);
  /* TODO: reason about bounds */
}

static const int32_t zetas[MLDSA_N] = {
    0,        25847,    -2608894, -518909,  237124,   -777960,  -876248,
    466468,   1826347,  2353451,  -359251,  -2091905, 3119733,  -2884855,
    3111497,  2680103,  2725464,  1024112,  -1079900, 3585928,  -549488,
    -1119584, 2619752,  -2108549, -2118186, -3859737, -1399561, -3277672,
    1757237,  -19422,   4010497,  280005,   2706023,  95776,    3077325,
    3530437,  -1661693, -3592148, -2537516, 3915439,  -3861115, -3043716,
    3574422,  -2867647, 3539968,  -300467,  2348700,  -539299,  -1699267,
    -1643818, 3505694,  -3821735, 3507263,  -2140649, -1600420, 3699596,
    811944,   531354,   954230,   3881043,  3900724,  -2556880, 2071892,
    -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455,  -1585221, -1257611, 1939314,  -4083598, -1000202, -3190144,
    -3157330, -3632928, 126922,   3412210,  -983419,  2147896,  2715295,
    -2967645, -3693493, -411027,  -2477047, -671102,  -1228525, -22981,
    -1308169, -381987,  1349076,  1852771,  -1430430, -3343383, 264944,
    508951,   3097992,  44288,    -1100098, 904516,   3958618,  -3724342,
    -8578,    1653064,  -3249728, 2389356,  -210977,  759969,   -1316856,
    189548,   -3553272, 3159746,  -1851402, -2409325, -177440,  1315589,
    1341330,  1285669,  -1584928, -812732,  -1439742, -3019102, -3881060,
    -3628969, 3839961,  2091667,  3407706,  2316500,  3817976,  -3342478,
    2244091,  -2446433, -3562462, 266997,   2434439,  -1235728, 3513181,
    -3520352, -3759364, -1197226, -3193378, 900702,   1859098,  909542,
    819034,   495491,   -1613174, -43260,   -522500,  -655327,  -3122442,
    2031748,  3207046,  -3556995, -525098,  -768622,  -3595838, 342297,
    286988,   -2437823, 4108315,  3437287,  -3342277, 1735879,  203044,
    2842341,  2691481,  -2590150, 1265009,  4055324,  1247620,  2486353,
    1595974,  -3767016, 1250494,  2635921,  -3548272, -2994039, 1869119,
    1903435,  -1050970, -1333058, 1237275,  -3318210, -1430225, -451100,
    1312455,  3306115,  -1962642, -1279661, 1917081,  -2546312, -1374803,
    1500165,  777191,   2235880,  3406031,  -542412,  -2831860, -1671176,
    -1846953, -2584293, -3724270, 594136,   -3776993, -2013608, 2432395,
    2454455,  -164721,  1957272,  3369112,  185531,   -1207385, -3183426,
    162844,   1616392,  3014001,  810149,   1652634,  -3694233, -1799107,
    -3038916, 3523897,  3866901,  269760,   2213111,  -975884,  1717735,
    472078,   -426683,  1723600,  -1803090, 1910376,  -1667432, -1104333,
    -260646,  -3833893, -2939036, -2235985, -420899,  -2286327, 183443,
    -976891,  1612842,  -3545687, -554416,  3919660,  -48306,   -1362209,
    3937738,  1400424,  -846154,  1976782};


/* mld_ntt_butterfly_block()
 *
 * Computes a block CT butterflies with a fixed twiddle factor,
 * using Montgomery multiplication.
 *
 * Parameters:
 * - r: Pointer to base of polynomial (_not_ the base of butterfly block)
 * - zeta: Twiddle factor to use for the butterfly. This must be in
 *         Montgomery form and signed canonical.
 * - start: Offset to the beginning of the butterfly block
 * - len: Index difference between coefficients subject to a butterfly
 * - bound: Ghost variable describing coefficient bound: Prior to `start`,
 *          coefficients must be bound by `bound + MLDSA_Q`. Post `start`,
 *          they must be bound by `bound`.
 * When this function returns, output coefficients in the index range
 * [start, start+2*len) have bound bumped to `bound + MLDSA_Q`.
 * Example:
 * - start=8, len=4
 *   This would compute the following four butterflies
 *          8     --    12
 *             9    --     13
 *                10   --     14
 *                   11   --     15
 * - start=4, len=2
 *   This would compute the following two butterflies
 *          4 -- 6
 *             5 -- 7
 */

/* Reference: Embedded in `ntt()` in the reference implementation. */
static void mld_ntt_butterfly_block(int32_t r[MLDSA_N], const int32_t zeta,
                                    const unsigned start, const unsigned len,
                                    const int32_t bound)
__contract__(
  requires(start < MLDSA_N)
  requires(1 <= len && len <= MLDSA_N / 2 && start + 2 * len <= MLDSA_N)
  requires(0 <= bound && bound < INT32_MAX - MLDSA_Q)
  requires(-MLDSA_Q_HALF < zeta && zeta < MLDSA_Q_HALF)
  requires(memory_no_alias(r, sizeof(int32_t) * MLDSA_N))
  requires(array_abs_bound(r, 0, start, bound + MLDSA_Q))
  requires(array_abs_bound(r, start, MLDSA_N, bound))
  assigns(memory_slice(r, sizeof(int32_t) * MLDSA_N))
  ensures(array_abs_bound(r, 0, start + 2*len, bound + MLDSA_Q))
  ensures(array_abs_bound(r, start + 2 * len, MLDSA_N, bound)))
{
  /* `bound` is a ghost variable only needed in the CBMC specification */
  unsigned j;
  ((void)bound);
  for (j = start; j < start + len; j++)
  __loop__(
    invariant(start <= j && j <= start + len)
    /*
     * Coefficients are updated in strided pairs, so the bounds for the
     * intermediate states alternate twice between the old and new bound
     */
    invariant(array_abs_bound(r, 0,           j,           bound + MLDSA_Q))
    invariant(array_abs_bound(r, j,           start + len, bound))
    invariant(array_abs_bound(r, start + len, j + len,     bound + MLDSA_Q))
    invariant(array_abs_bound(r, j + len,     MLDSA_N,     bound)))
  {
    int32_t t;
    t = mld_fqmul(r[j + len], zeta);
    r[j + len] = r[j] - t;
    r[j] = r[j] + t;
  }
}

/* mld_ntt_layer()
 *
 * Compute one layer of forward NTT
 *
 * Parameters:
 * - r:     Pointer to base of polynomial
 * - layer: Indicates which layer is being applied.
 */

/* Reference: Embedded in `ntt()` in the reference implementation. */
static void mld_ntt_layer(int32_t r[MLDSA_N], const unsigned layer)
__contract__(
  requires(memory_no_alias(r, sizeof(int32_t) * MLDSA_N))
  requires(1 <= layer && layer <= 8)
  requires(array_abs_bound(r, 0, MLDSA_N, layer * MLDSA_Q))
  assigns(memory_slice(r, sizeof(int32_t) * MLDSA_N))
  ensures(array_abs_bound(r, 0, MLDSA_N, (layer + 1) * MLDSA_Q)))
{
  unsigned start, k, len;
  /* Twiddle factors for layer n are at indices 2^(n-1)..2^n-1. */
  k = 1u << (layer - 1);
  len = MLDSA_N >> layer;
  for (start = 0; start < MLDSA_N; start += 2 * len)
  __loop__(
    invariant(start < MLDSA_N + 2 * len)
    invariant(k <= MLDSA_N)
    invariant(2 * len * k == start + MLDSA_N)
    invariant(array_abs_bound(r, 0, start, layer * MLDSA_Q + MLDSA_Q))
    invariant(array_abs_bound(r, start, MLDSA_N, layer * MLDSA_Q)))
  {
    int32_t zeta = zetas[k++];
    mld_ntt_butterfly_block(r, zeta, start, len, layer * MLDSA_Q);
  }
}


void ntt(int32_t a[MLDSA_N])
{
  unsigned int layer;

  for (layer = 1; layer < 9; layer++)
  __loop__(
    invariant(1 <= layer && layer <= 9)
    invariant(array_abs_bound(a, 0, MLDSA_N, layer * MLDSA_Q))
  )
  {
    mld_ntt_layer(a, layer);
  }

  /* When the loop exits, layer == 9, so the loop invariant  */
  /* directly implies the postcondition in that coefficients */
  /* are bounded in magnitude by 9 * MLDSA_Q                 */
}


/*************************************************
 * Name:        invntt_tomont
 *
 * Description: Inverse NTT and multiplication by Montgomery factor 2^32.
 *              In-place. No modular reductions after additions or
 *              subtractions; input coefficients need to be smaller than
 *              MLDSA_Q in absolute value. Output coefficient are smaller than
 *MLDSA_Q in absolute value.
 *
 * Arguments:   - uint32_t p[MLDSA_N]: input/output coefficient array
 **************************************************/
void invntt_tomont(int32_t a[MLDSA_N])
{
  unsigned int start, len, j, k;
  int32_t t, zeta;
  const int32_t f = 41978; /* mont^2/256 */

  k = 256;
  for (len = 1; len < MLDSA_N; len <<= 1)
  {
    for (start = 0; start < MLDSA_N; start = j + len)
    {
      zeta = -zetas[--k];
      for (j = start; j < start + len; ++j)
      {
        t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = mld_fqmul(a[j + len], zeta);
      }
    }
  }

  for (j = 0; j < MLDSA_N; ++j)
  {
    a[j] = mld_fqmul(a[j], f);
  }
}
