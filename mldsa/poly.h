/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "cbmc.h"
#include "params.h"
#include "reduce.h"

typedef struct
{
  int32_t coeffs[MLDSA_N];
} poly;

#define poly_reduce MLD_NAMESPACE(poly_reduce)
void poly_reduce(poly *a)
__contract__(
  requires(memory_no_alias(a, sizeof(poly)))
  requires(forall(k0, 0, MLDSA_N, a->coeffs[k0] <= REDUCE_DOMAIN_MAX)) 
  assigns(memory_slice(a, sizeof(poly)))
  ensures(array_bound(a->coeffs, 0, MLDSA_N, -REDUCE_RANGE_MAX, REDUCE_RANGE_MAX))
);

#define poly_caddq MLD_NAMESPACE(poly_caddq)
void poly_caddq(poly *a);

#define poly_add MLD_NAMESPACE(poly_add)
void poly_add(poly *c, const poly *a, const poly *b)
__contract__(
  requires(memory_no_alias(c, sizeof(poly)))
  requires(memory_no_alias(a, sizeof(poly)))
  requires(memory_no_alias(b, sizeof(poly)))
  requires(forall(k0, 0, MLDSA_N, (int64_t) a->coeffs[k0] + b->coeffs[k0] <= INT32_MAX))
  requires(forall(k1, 0, MLDSA_N, (int64_t) a->coeffs[k1] + b->coeffs[k1] >= INT32_MIN))
  ensures(forall(k, 0, MLDSA_N, c->coeffs[k] == a->coeffs[k] + b->coeffs[k]))
  assigns(memory_slice(c, sizeof(poly)))
);

#define poly_sub MLD_NAMESPACE(poly_sub)
void poly_sub(poly *c, const poly *a, const poly *b)
__contract__(
  requires(memory_no_alias(c, sizeof(poly)))
  requires(memory_no_alias(a, sizeof(poly)))
  requires(memory_no_alias(b, sizeof(poly)))
  requires(forall(k0, 0, MLDSA_N, (int64_t) a->coeffs[k0] - b->coeffs[k0] <= INT32_MAX))
  requires(forall(k1, 0, MLDSA_N, (int64_t) a->coeffs[k1] - b->coeffs[k1] >= INT32_MIN))
  ensures(forall(k, 0, MLDSA_N, c->coeffs[k] == a->coeffs[k] - b->coeffs[k]))
  assigns(memory_slice(c, sizeof(poly))));

#define poly_shiftl MLD_NAMESPACE(poly_shiftl)
void poly_shiftl(poly *a)
__contract__(
  requires(memory_no_alias(a, sizeof(poly)))
  requires(array_abs_bound(a->coeffs, 0, MLDSA_N, 1 << (31 - MLDSA_D) - 1))
  assigns(memory_slice(a, sizeof(poly)))
);

#define poly_ntt MLD_NAMESPACE(poly_ntt)
void poly_ntt(poly *a);
#define poly_invntt_tomont MLD_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *a);
#define poly_pointwise_montgomery MLD_NAMESPACE(poly_pointwise_montgomery)
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

#define poly_power2round MLD_NAMESPACE(poly_power2round)
void poly_power2round(poly *a1, poly *a0, const poly *a);

#define poly_decompose MLD_NAMESPACE(poly_decompose)
void poly_decompose(poly *a1, poly *a0, const poly *a)
__contract__(
  requires(memory_no_alias(a1,  sizeof(poly)))
  requires(memory_no_alias(a0, sizeof(poly)))
  requires(memory_no_alias(a, sizeof(poly)))
  requires(array_bound(a->coeffs, 0, MLDSA_N, 0, MLDSA_Q))
  assigns(memory_slice(a1, sizeof(poly)))
  assigns(memory_slice(a0, sizeof(poly)))
  ensures(array_bound(a1->coeffs, 0, MLDSA_N, 0, (MLDSA_Q-1)/(2*MLDSA_GAMMA2)))
  ensures(array_abs_bound(a0->coeffs, 0, MLDSA_N, MLDSA_GAMMA2+1))
);

#define poly_make_hint MLD_NAMESPACE(poly_make_hint)
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1)
__contract__(
  requires(memory_no_alias(h,  sizeof(poly)))
  requires(memory_no_alias(a0, sizeof(poly)))
  requires(memory_no_alias(a1, sizeof(poly)))
  assigns(memory_slice(h, sizeof(poly)))
  ensures(return_value <= MLDSA_N)
);

#define poly_use_hint MLD_NAMESPACE(poly_use_hint)
void poly_use_hint(poly *b, const poly *a, const poly *h)
__contract__(
  requires(memory_no_alias(a,  sizeof(poly)))
  requires(memory_no_alias(b, sizeof(poly)))
  requires(memory_no_alias(h, sizeof(poly)))
  requires(array_bound(a->coeffs, 0, MLDSA_N, 0, MLDSA_Q))
  requires(array_bound(h->coeffs, 0, MLDSA_N, 0, 2))
  assigns(memory_slice(b, sizeof(poly)))
  ensures(array_bound(b->coeffs, 0, MLDSA_N, 0, (MLDSA_Q-1)/(2*MLDSA_GAMMA2)))
);

#define poly_chknorm MLD_NAMESPACE(poly_chknorm)
int poly_chknorm(const poly *a, int32_t B);

#define poly_uniform MLD_NAMESPACE(poly_uniform)
void poly_uniform(poly *a, const uint8_t seed[MLDSA_SEEDBYTES], uint16_t nonce);

#define poly_uniform_eta MLD_NAMESPACE(poly_uniform_eta)
void poly_uniform_eta(poly *a, const uint8_t seed[MLDSA_CRHBYTES],
                      uint16_t nonce);

#define poly_uniform_gamma1 MLD_NAMESPACE(poly_uniform_gamma1)
void poly_uniform_gamma1(poly *a, const uint8_t seed[MLDSA_CRHBYTES],
                         uint16_t nonce);

#define poly_challenge MLD_NAMESPACE(poly_challenge)
void poly_challenge(poly *c, const uint8_t seed[MLDSA_CTILDEBYTES]);

#define polyeta_pack MLD_NAMESPACE(polyeta_pack)
void polyeta_pack(uint8_t *r, const poly *a)
__contract__(
  requires(memory_no_alias(r, MLDSA_POLYETA_PACKEDBYTES))
  requires(memory_no_alias(a, sizeof(poly)))
  requires(array_abs_bound(a->coeffs, 0, MLDSA_N, MLDSA_ETA + 1))
  assigns(memory_slice(r, MLDSA_POLYETA_PACKEDBYTES))
);

/*
 * polyeta_unpack produces coefficients in [-MLDSA_ETA,MLDSA_ETA] for
 * well-formed inputs (i.e., those produced by polyeta_pack).
 * However, when passed an arbitrary byte array, it may produce smaller values,
 * i.e, values in [MLD_POLYETA_UNPACK_LOWER_BOUND,MLDSA_ETA]
 * Even though this should never happen, we use use the bound for arbitrary
 * inputs in the CBMC proofs.
 */
#if MLDSA_ETA == 2
#define MLD_POLYETA_UNPACK_LOWER_BOUND (-5)
#elif MLDSA_ETA == 4
#define MLD_POLYETA_UNPACK_LOWER_BOUND (-11)
#else
#error "Invalid value of MLDSA_ETA"
#endif

#define polyeta_unpack MLD_NAMESPACE(polyeta_unpack)
void polyeta_unpack(poly *r, const uint8_t *a)
__contract__(
  requires(memory_no_alias(r, sizeof(poly)))
  requires(memory_no_alias(a, MLDSA_POLYETA_PACKEDBYTES))
  assigns(memory_slice(r, sizeof(poly)))
  ensures(array_bound(r->coeffs, 0, MLDSA_N, MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1))
);

#define polyt1_pack MLD_NAMESPACE(polyt1_pack)
void polyt1_pack(uint8_t *r, const poly *a)
__contract__(
  requires(memory_no_alias(r, MLDSA_POLYT1_PACKEDBYTES))
  requires(memory_no_alias(a, sizeof(poly)))
  requires(array_bound(a->coeffs, 0, MLDSA_N, 0, 1 << 10))
  assigns(object_whole(r))
);

#define polyt1_unpack MLD_NAMESPACE(polyt1_unpack)
void polyt1_unpack(poly *r, const uint8_t *a)
__contract__(
  requires(memory_no_alias(r, sizeof(poly)))
  requires(memory_no_alias(a, MLDSA_POLYT1_PACKEDBYTES))
  assigns(memory_slice(r, sizeof(poly)))
  ensures(array_bound(r->coeffs, 0, MLDSA_N, 0, 1 << 10))
);

#define polyt0_pack MLD_NAMESPACE(polyt0_pack)
void polyt0_pack(uint8_t *r, const poly *a)
__contract__(
  requires(memory_no_alias(r, MLDSA_POLYT0_PACKEDBYTES))
  requires(memory_no_alias(a, sizeof(poly)))
  requires(array_bound(a->coeffs, 0, MLDSA_N, -(1<<(MLDSA_D-1)) + 1, (1<<(MLDSA_D-1)) + 1))
  assigns(memory_slice(r, MLDSA_POLYT0_PACKEDBYTES))
);


#define polyt0_unpack MLD_NAMESPACE(polyt0_unpack)
void polyt0_unpack(poly *r, const uint8_t *a)
__contract__(
  requires(memory_no_alias(r, sizeof(poly)))
  requires(memory_no_alias(a, MLDSA_POLYT0_PACKEDBYTES))
  assigns(memory_slice(r, sizeof(poly)))
  ensures(array_bound(r->coeffs, 0, MLDSA_N, -(1<<(MLDSA_D-1)) + 1, (1<<(MLDSA_D-1)) + 1))
);

#define polyz_pack MLD_NAMESPACE(polyz_pack)
void polyz_pack(uint8_t *r, const poly *a)
__contract__(
  requires(memory_no_alias(r, MLDSA_POLYZ_PACKEDBYTES))
  requires(memory_no_alias(a, sizeof(poly)))
  requires(array_bound(a->coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1))
  assigns(object_whole(r))
);

#define polyz_unpack MLD_NAMESPACE(polyz_unpack)
void polyz_unpack(poly *r, const uint8_t *a)
__contract__(
  requires(memory_no_alias(r, sizeof(poly)))
  requires(memory_no_alias(a, MLDSA_POLYZ_PACKEDBYTES))
  assigns(object_whole(r))
  ensures(array_bound(r->coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1))
);


#define polyw1_pack MLD_NAMESPACE(polyw1_pack)
void polyw1_pack(uint8_t *r, const poly *a)
#if MLDSA_GAMMA2 == (MLDSA_Q - 1) / 32
__contract__(
  requires(memory_no_alias(r, MLDSA_POLYW1_PACKEDBYTES))
  requires(memory_no_alias(a, sizeof(poly)))
  requires(array_bound(a->coeffs, 0, MLDSA_N, 0, 16))
  assigns(object_whole(r)));
#elif MLDSA_GAMMA2 == (MLDSA_Q - 1) / 88
__contract__(
  requires(memory_no_alias(r, MLDSA_POLYW1_PACKEDBYTES))
  requires(memory_no_alias(a, sizeof(poly)))
  requires(array_bound(a->coeffs, 0, MLDSA_N, 0, 44))
  assigns(object_whole(r)));
#else
#error "Invalid value of MLDSA_GAMMA2"
#endif


#endif
