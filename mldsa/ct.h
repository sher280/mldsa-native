/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLD_CT_H
#define MLD_CT_H

#include <stdint.h>
#include "cbmc.h"
#include "common.h"

/* TODO: add documentation here */
/* TODO: add MLD_CONFIG_NO_ASM_VALUE_BARRIER to config.h */
#if defined(MLD_HAVE_INLINE_ASM) && !defined(MLD_CONFIG_NO_ASM_VALUE_BARRIER)
#define MLD_USE_ASM_VALUE_BARRIER
#endif


#if !defined(MLD_USE_ASM_VALUE_BARRIER)
/*
 * Declaration of global volatile that the global value barrier
 * is loading from and masking with.
 */
#define mld_ct_opt_blocker_u64 MLD_NAMESPACE(ct_opt_blocker_u64)
extern volatile uint64_t mld_ct_opt_blocker_u64;


/* Helper functions for obtaining global masks of various sizes */

/* This contract is not proved but treated as an axiom.
 *
 * Its validity relies on the assumption that the global opt-blocker
 * constant mld_ct_opt_blocker_u64 is not modified.
 */
static MLD_INLINE uint64_t mld_ct_get_optblocker_u64(void)
__contract__(ensures(return_value == 0)) { return mld_ct_opt_blocker_u64; }

/* TODO: proof */
static MLD_INLINE int64_t mld_ct_get_optblocker_i64(void)
__contract__(ensures(return_value == 0)) { return (int64_t)mld_ct_get_optblocker_u64(); }
/* TODO: proof */
static MLD_INLINE uint32_t mld_ct_get_optblocker_u32(void)
__contract__(ensures(return_value == 0)) { return (uint32_t)mld_ct_get_optblocker_u64(); }

/* Opt-blocker based implementation of value barriers */
/* TODO: proof */
static MLD_INLINE int64_t mld_value_barrier_i64(int64_t b)
__contract__(ensures(return_value == b)) { return (b ^ mld_ct_get_optblocker_i64()); }
/* TODO: proof */
static MLD_INLINE uint32_t mld_value_barrier_u32(uint32_t b)
__contract__(ensures(return_value == b)) { return (b ^ mld_ct_get_optblocker_u32()); }


#else  /* !MLD_USE_ASM_VALUE_BARRIER */
static MLD_INLINE int64_t mld_value_barrier_i64(int64_t b)
__contract__(ensures(return_value == b))
{
  __asm__("" : "+r"(b));
  return b;
}

static MLD_INLINE uint32_t mld_value_barrier_u32(uint32_t b)
__contract__(ensures(return_value == b))
{
  __asm__("" : "+r"(b));
  return b;
}
#endif /* MLD_USE_ASM_VALUE_BARRIER */

/*************************************************
 * Name:        mld_ct_sel_int32
 *
 * Description: Functionally equivalent to cond ? a : b,
 *              but implemented with guards against
 *              compiler-introduced branches.
 *
 * Arguments:   int32_t a:       First alternative
 *              int32_t b:       Second alternative
 *              uint32_t cond:   Condition variable.
 *
 *
 **************************************************/
static MLD_INLINE int32_t mld_ct_sel_int32(int32_t a, int32_t b, uint32_t cond)
/* TODO: proof */
__contract__(
  requires(cond == 0x0 || cond == 0xFFFFFFFF)
  ensures(return_value == (cond ? a : b))
)
{
  uint32_t au = a, bu = b;
  uint32_t res = bu ^ (mld_value_barrier_u32(cond) & (au ^ bu));
  return (int32_t)res;
}


/*************************************************
 * Name:        mld_ct_cmask_neg_i32
 *
 * Description: Return 0 if input is non-negative, and -1 otherwise.
 *
 * Arguments:   int32_t x: Value to be converted into a mask
 *
 **************************************************/
/* TODO: proof */
static MLD_INLINE uint32_t mld_ct_cmask_neg_i32(int32_t x)
__contract__(ensures(return_value == ((x < 0) ? 0xFFFFFFFF : 0)))
{
  int64_t tmp = mld_value_barrier_i64((int64_t)x);
  tmp >>= 31;
  return (uint32_t)tmp;
}

/*************************************************
 * Name:        mld_ct_abs_i32
 *
 * Description: Return -x if x<0, x otherwise
 *
 * Arguments:   int32_t x: Input value
 *
 **************************************************/
/* TODO: proof */
static MLD_INLINE uint32_t mld_ct_abs_i32(int32_t x)
__contract__(ensures(return_value == ((x < 0) ? -x : x)))
{
  return mld_ct_sel_int32(-x, x, mld_ct_cmask_neg_i32(x));
}


#endif /* !MLD_CT_H */
