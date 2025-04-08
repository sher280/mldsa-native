/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "reduce.h"
#include <stdint.h>
#include "params.h"

/*************************************************
 * Name:        mlk_cast_uint32_to_int32
 *
 * Description: Cast uint32 value to int32
 *
 * Returns:
 *   input x in     0 .. 2^31-1: returns value unchanged
 *   input x in  2^31 .. 2^32-1: returns (x - 2^32)
 **************************************************/
#ifdef CBMC
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#endif
static int32_t mld_cast_uint32_to_int32(uint32_t x)
{
  /*
   * PORTABILITY: This relies on uint32_t -> int32_t
   * being implemented as the inverse of int32_t -> uint32_t,
   * which is implementation-defined (C99 6.3.1.3 (3))
   * CBMC (correctly) fails to prove this conversion is OK,
   * so we have to suppress that check here
   */
  return (int32_t)x;
}
#ifdef CBMC
#pragma CPROVER check pop
#endif

int32_t montgomery_reduce(int64_t a)
{
  /* check-magic: 58728449 == unsigned_mod(pow(MLDSA_Q, -1, 2^32), 2^32) */
  const uint64_t QINV = 58728449;

  /*  Compute a*q^{-1} mod 2^32 in unsigned representatives */
  const uint32_t a_reduced = a & UINT32_MAX;
  const uint32_t a_inverted = (a_reduced * QINV) & UINT32_MAX;

  /* Lift to signed canonical representative mod 2^16. */
  const int32_t t = mld_cast_uint32_to_int32(a_inverted);

  int64_t r;

  r = a - ((int64_t)t * MLDSA_Q);

  /*
   * PORTABILITY: Right-shift on a signed integer is, strictly-speaking,
   * implementation-defined for negative left argument. Here,
   * we assume it's sign-preserving "arithmetic" shift right. (C99 6.5.7 (5))
   */
  r = r >> 32;
  return (int32_t)r;
}

/*************************************************
 * Name:        reduce32
 *
 * Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
 *              compute r \equiv a (mod MLDSA_Q) such that -6283008 <= r <=
 *6283008.
 *
 * Arguments:   - int32_t: finite field element a
 *
 * Returns r.
 **************************************************/
int32_t reduce32(int32_t a)
{
  int32_t t;

  t = (a + (1 << 22)) >> 23;
  t = a - t * MLDSA_Q;
  cassert((t - a) % MLDSA_Q == 0);
  return t;
}

/*************************************************
 * Name:        caddq
 *
 * Description: Add MLDSA_Q if input coefficient is negative.
 *
 * Arguments:   - int32_t: finite field element a
 *
 * Returns r.
 **************************************************/
int32_t caddq(int32_t a)
{
  a += (a >> 31) & MLDSA_Q;
  return a;
}

/*************************************************
 * Name:        freeze
 *
 * Description: For finite field element a, compute standard
 *              representative r = a mod^+ MLDSA_Q.
 *
 * Arguments:   - int32_t: finite field element a
 *
 * Returns r.
 **************************************************/
int32_t freeze(int32_t a)
{
  a = reduce32(a);
  a = caddq(a);
  return a;
}
