/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "cbmc.h"
#include "params.h"

#define power2round MLD_NAMESPACE(power2round)
/*************************************************
 * Name:        power2round
 *
 * Description: For finite field element a, compute a0, a1 such that
 *              a mod^+ MLDSA_Q = a1*2^MLDSA_D + a0 with -2^{MLDSA_D-1} < a0 <=
 *              2^{MLDSA_D-1}. Assumes a to be standard representative.
 *
 * Arguments:   - int32_t a: input element
 *              - int32_t *a0: pointer to output element a0
 *              - int32_t *a1: pointer to output element a1
 *
 * Reference: a1 is passed as a return value instead
 **************************************************/
void power2round(int32_t *a0, int32_t *a1, int32_t a);

#define decompose MLD_NAMESPACE(decompose)
int32_t decompose(int32_t *a0, int32_t a);

#define make_hint MLD_NAMESPACE(make_hint)
unsigned int make_hint(int32_t a0, int32_t a1)
__contract__(
  ensures(return_value >= 0 && return_value <= 1)
);

#define use_hint MLD_NAMESPACE(use_hint)
int32_t use_hint(int32_t a, unsigned int hint);

#endif
