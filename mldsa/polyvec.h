/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "cbmc.h"
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length MLDSA_L */
typedef struct
{
  poly vec[MLDSA_L];
} polyvecl;

#define polyvecl_uniform_eta MLD_NAMESPACE(polyvecl_uniform_eta)
void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES],
                          uint16_t nonce);

#define polyvecl_uniform_gamma1 MLD_NAMESPACE(polyvecl_uniform_gamma1)
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES],
                             uint16_t nonce);

#define polyvecl_reduce MLD_NAMESPACE(polyvecl_reduce)
void polyvecl_reduce(polyvecl *v);

#define polyvecl_add MLD_NAMESPACE(polyvecl_add)
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);

#define polyvecl_ntt MLD_NAMESPACE(polyvecl_ntt)
void polyvecl_ntt(polyvecl *v);
#define polyvecl_invntt_tomont MLD_NAMESPACE(polyvecl_invntt_tomont)
void polyvecl_invntt_tomont(polyvecl *v);
#define polyvecl_pointwise_poly_montgomery \
  MLD_NAMESPACE(polyvecl_pointwise_poly_montgomery)
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a,
                                        const polyvecl *v);
#define polyvecl_pointwise_acc_montgomery \
  MLD_NAMESPACE(polyvecl_pointwise_acc_montgomery)
void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u,
                                       const polyvecl *v);


#define polyvecl_chknorm MLD_NAMESPACE(polyvecl_chknorm)
int polyvecl_chknorm(const polyvecl *v, int32_t B);



/* Vectors of polynomials of length MLDSA_K */
typedef struct
{
  poly vec[MLDSA_K];
} polyveck;

#define polyveck_uniform_eta MLD_NAMESPACE(polyveck_uniform_eta)
void polyveck_uniform_eta(polyveck *v, const uint8_t seed[MLDSA_CRHBYTES],
                          uint16_t nonce);

#define polyveck_reduce MLD_NAMESPACE(polyveck_reduce)
void polyveck_reduce(polyveck *v);
#define polyveck_caddq MLD_NAMESPACE(polyveck_caddq)
void polyveck_caddq(polyveck *v);

#define polyveck_add MLD_NAMESPACE(polyveck_add)
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_sub MLD_NAMESPACE(polyveck_sub)
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_shiftl MLD_NAMESPACE(polyveck_shiftl)
void polyveck_shiftl(polyveck *v);

#define polyveck_ntt MLD_NAMESPACE(polyveck_ntt)
void polyveck_ntt(polyveck *v);
#define polyveck_invntt_tomont MLD_NAMESPACE(polyveck_invntt_tomont)
void polyveck_invntt_tomont(polyveck *v);
#define polyveck_pointwise_poly_montgomery \
  MLD_NAMESPACE(polyveck_pointwise_poly_montgomery)
void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a,
                                        const polyveck *v);

#define polyveck_chknorm MLD_NAMESPACE(polyveck_chknorm)
int polyveck_chknorm(const polyveck *v, int32_t B);

#define polyveck_power2round MLD_NAMESPACE(polyveck_power2round)
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_decompose MLD_NAMESPACE(polyveck_decompose)
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);


#define polyveck_make_hint MLD_NAMESPACE(polyveck_make_hint)
unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0,
                                const polyveck *v1)
__contract__(
  requires(memory_no_alias(h,  sizeof(polyveck)))
  requires(memory_no_alias(v0, sizeof(polyveck)))
  requires(memory_no_alias(v1, sizeof(polyveck)))
  assigns(object_whole(h))
  ensures(return_value <= MLDSA_N * MLDSA_K)
);

#define polyveck_use_hint MLD_NAMESPACE(polyveck_use_hint)
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

#define polyveck_pack_w1 MLD_NAMESPACE(polyveck_pack_w1)
void polyveck_pack_w1(uint8_t r[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES],
                      const polyveck *w1);

#define polyveck_pack_eta MLD_NAMESPACE(polyveck_pack_eta)
void polyveck_pack_eta(uint8_t r[MLDSA_K * MLDSA_POLYETA_PACKEDBYTES],
                       const polyveck *p)
__contract__(                 
  requires(memory_no_alias(r,  MLDSA_K * MLDSA_POLYETA_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(polyveck)))
  requires(forall(k1, 0, MLDSA_K,
    array_abs_bound(p->vec[k1].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
  assigns(object_whole(r))
);

#define polyvecl_pack_eta MLD_NAMESPACE(polyvecl_pack_eta)
void polyvecl_pack_eta(uint8_t r[MLDSA_L * MLDSA_POLYETA_PACKEDBYTES],
                       const polyvecl *p)
__contract__(                 
  requires(memory_no_alias(r,  MLDSA_L * MLDSA_POLYETA_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(polyvecl)))
  requires(forall(k1, 0, MLDSA_L,
    array_abs_bound(p->vec[k1].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
  assigns(object_whole(r))
);

#define polyvecl_pack_z MLD_NAMESPACE(polyvecl_pack_z)
void polyvecl_pack_z(uint8_t r[MLDSA_L * MLDSA_POLYZ_PACKEDBYTES],
                     const polyvecl *p)
__contract__(                 
  requires(memory_no_alias(r,  MLDSA_L * MLDSA_POLYZ_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(polyvecl)))
  requires(forall(k1, 0, MLDSA_L,
                  array_bound(p->vec[k1].coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1)))
  assigns(object_whole(r))
);

#define polyveck_pack_t0 MLD_NAMESPACE(polyveck_pack_t0)
void polyveck_pack_t0(uint8_t r[MLDSA_K * MLDSA_POLYT0_PACKEDBYTES],
                      const polyveck *p)
__contract__(                 
  requires(memory_no_alias(r,  MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(polyveck)))
  requires(forall(k0, 0, MLDSA_K,
    array_bound(p->vec[k0].coeffs, 0, MLDSA_N, -(1<<(MLDSA_D-1)) + 1, (1<<(MLDSA_D-1)) + 1)))
  assigns(object_whole(r))
);

#define polyvecl_unpack_eta MLD_NAMESPACE(polyvecl_unpack_eta)
void polyvecl_unpack_eta(polyvecl *p,
                         const uint8_t r[MLDSA_L * MLDSA_POLYETA_PACKEDBYTES])
__contract__(                 
  requires(memory_no_alias(r,  MLDSA_L * MLDSA_POLYETA_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(polyvecl)))
  assigns(object_whole(p))
  ensures(forall(k1, 0, MLDSA_L,
    array_bound(p->vec[k1].coeffs, 0, MLDSA_N, MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1)))
);

#define polyveck_unpack_eta MLD_NAMESPACE(polyveck_unpack_eta)
void polyveck_unpack_eta(polyveck *p,
                         const uint8_t r[MLDSA_K * MLDSA_POLYETA_PACKEDBYTES])
__contract__(                 
  requires(memory_no_alias(r,  MLDSA_K * MLDSA_POLYETA_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(polyveck)))
  assigns(object_whole(p))
  ensures(forall(k1, 0, MLDSA_K,
    array_bound(p->vec[k1].coeffs, 0, MLDSA_N, MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1)))
);

#define polyveck_unpack_t0 MLD_NAMESPACE(polyveck_unpack_t0)
void polyveck_unpack_t0(polyveck *p,
                        const uint8_t r[MLDSA_K * MLDSA_POLYT0_PACKEDBYTES])
__contract__(                 
  requires(memory_no_alias(r,  MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(polyveck)))
  assigns(object_whole(p))
  ensures(forall(k1, 0, MLDSA_K,
    array_bound(p->vec[k1].coeffs, 0, MLDSA_N, -(1<<(MLDSA_D-1)) + 1, (1<<(MLDSA_D-1)) + 1)))
);

#define polyvec_matrix_expand MLD_NAMESPACE(polyvec_matrix_expand)
void polyvec_matrix_expand(polyvecl mat[MLDSA_K],
                           const uint8_t rho[MLDSA_SEEDBYTES]);

#define polyvec_matrix_pointwise_montgomery \
  MLD_NAMESPACE(polyvec_matrix_pointwise_montgomery)
void polyvec_matrix_pointwise_montgomery(polyveck *t,
                                         const polyvecl mat[MLDSA_K],
                                         const polyvecl *v);

#endif
