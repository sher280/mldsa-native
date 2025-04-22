/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MLD_NTT_H
#define MLD_NTT_H

#include <stdint.h>
#include "cbmc.h"
#include "common.h"

/* Absolute exclusive upper bound for the output of the forward NTT */
#define MLD_NTT_BOUND (9 * MLDSA_Q)

#define ntt MLD_NAMESPACE(ntt)
/*************************************************
 * Name:        ntt
 *
 * Description: Computes number-theoretic transform (NTT) of
 *              a polynomial in place.
 *
 *              The input is assumed to be in normal order and
 *              coefficient-wise bound by MLDSA_Q in absolute value.
 *
 *              The output polynomial is in bitreversed order, and
 *              coefficient-wise bound by MLD_NTT_BOUND in absolute value.
 *
 *              (NOTE: Sometimes the input to the NTT is actually smaller,
 *               which gives better bounds.)
 *
 * Arguments:   - int32_t a[MLDSA_N]: pointer to in/output polynomial
 *
 * Specification: Implements [FIPS 204, Algorithm 41, NTT]
 *
 **************************************************/
void ntt(int32_t a[MLDSA_N])
__contract__(
  requires(memory_no_alias(a, MLDSA_N * sizeof(int32_t)))
  requires(array_abs_bound(a, 0, MLDSA_N, MLDSA_Q))
  assigns(memory_slice(a, MLDSA_N * sizeof(int32_t)))
  ensures(array_abs_bound(a, 0, MLDSA_N, MLD_NTT_BOUND))
);

#define invntt_tomont MLD_NAMESPACE(invntt_tomont)
/*************************************************
 * Name:        invntt_tomont
 *
 * Description: Inverse NTT and multiplication by Montgomery factor 2^32.
 *              In-place. No modular reductions after additions or
 *              subtractions; input coefficients need to be smaller than
 *              MLDSA_Q in absolute value. Output coefficient are smaller than
 *              MLDSA_Q in absolute value.
 *
 * Arguments:   - uint32_t a[MLDSA_N]: input/output coefficient array
 **************************************************/
void invntt_tomont(int32_t a[MLDSA_N])
__contract__(
  requires(memory_no_alias(a, MLDSA_N * sizeof(int32_t)))
  requires(array_abs_bound(a, 0, MLDSA_N, MLDSA_Q))
  assigns(memory_slice(a, MLDSA_N * sizeof(int32_t)))
  ensures(array_abs_bound(a, 0, MLDSA_N, MLDSA_Q))
);

#endif /* !MLD_NTT_H */
