/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MLD_REDUCE_H
#define MLD_REDUCE_H

#include <stdint.h>
#include "cbmc.h"
#include "common.h"

#define MONT -4186625 /* 2^32 % MLDSA_Q */
#define REDUCE_DOMAIN_MAX (INT32_MAX - (1 << 22))
#define REDUCE_RANGE_MAX 6283009
#define MONTGOMERY_REDUCE_DOMAIN_MAX ((int64_t)INT32_MIN * INT32_MIN)

#define montgomery_reduce MLD_NAMESPACE(montgomery_reduce)
/*************************************************
 * Name:        montgomery_reduce
 *
 * Description: For finite field element a with
 *              -2^{31}MLDSA_Q <= a <= MLDSA_Q*2^31,
 *              compute r \equiv a*2^{-32} (mod MLDSA_Q) such that
 *              -MLDSA_Q < r < MLDSA_Q.
 *              If the output bounds are not required, the inputs can be larger
 *              (up to INT64_MAX - (2^31 * MLDSA_Q) > INT32_MAX^2)
 *
 * Arguments:   - int64_t: finite field element a
 *
 * Returns r.
 **************************************************/
int32_t montgomery_reduce(int64_t a)
__contract__(
  requires(a >= -MONTGOMERY_REDUCE_DOMAIN_MAX && a <= MONTGOMERY_REDUCE_DOMAIN_MAX)
);

#define reduce32 MLD_NAMESPACE(reduce32)
/*************************************************
 * Name:        reduce32
 *
 * Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
 *              compute r \equiv a (mod MLDSA_Q) such that
 *              -REDUCE_RANGE_MAX <= r < REDUCE_RANGE_MAX.
 *
 * Arguments:   - int32_t: finite field element a
 *
 * Returns r.
 **************************************************/
int32_t reduce32(int32_t a)
__contract__(
  requires(a <= REDUCE_DOMAIN_MAX)
  ensures(return_value >= -REDUCE_RANGE_MAX)
  ensures(return_value <   REDUCE_RANGE_MAX)
);

#define caddq MLD_NAMESPACE(caddq)
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
__contract__(
  requires(a > -MLDSA_Q)
  requires(a < MLDSA_Q)
  ensures(return_value >= 0)
  ensures(return_value < MLDSA_Q)
  ensures(return_value == (a >= 0) ? a : (a + MLDSA_Q))
);


#endif /* !MLD_REDUCE_H */
