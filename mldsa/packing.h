/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define pack_pk MLD_NAMESPACE(pack_pk)
void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES], const polyveck *t1)
__contract__(
  requires(memory_no_alias(pk, CRYPTO_PUBLICKEYBYTES))
  requires(memory_no_alias(rho, MLDSA_SEEDBYTES))
  requires(memory_no_alias(t1, sizeof(polyveck)))
  requires(forall(k0, 0, MLDSA_K,
    array_bound(t1->vec[k0].coeffs, 0, MLDSA_N, 0, 1 << 10)))
  assigns(object_whole(pk))
);


#define pack_sk MLD_NAMESPACE(pack_sk)
void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES],
             const uint8_t tr[MLDSA_TRBYTES],
             const uint8_t key[MLDSA_SEEDBYTES], const polyveck *t0,
             const polyvecl *s1, const polyveck *s2)
__contract__(
  requires(memory_no_alias(sk, CRYPTO_SECRETKEYBYTES))
  requires(memory_no_alias(rho, MLDSA_SEEDBYTES))
  requires(memory_no_alias(tr, MLDSA_TRBYTES))
  requires(memory_no_alias(key, MLDSA_SEEDBYTES))
  requires(memory_no_alias(t0, sizeof(polyveck)))
  requires(memory_no_alias(s1, sizeof(polyvecl)))
  requires(memory_no_alias(s2, sizeof(polyveck)))
  requires(forall(k0, 0, MLDSA_K,
    array_bound(t0->vec[k0].coeffs, 0, MLDSA_N, -(1<<(MLDSA_D-1)) + 1, (1<<(MLDSA_D-1)) + 1)))
  requires(forall(k1, 0, MLDSA_L,
    array_abs_bound(s1->vec[k1].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
  requires(forall(k2, 0, MLDSA_K,
    array_abs_bound(s2->vec[k2].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
  assigns(object_whole(sk))
);


#define pack_sig MLD_NAMESPACE(pack_sig)
void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[MLDSA_CTILDEBYTES],
              const polyvecl *z, const polyveck *h);

#define unpack_pk MLD_NAMESPACE(unpack_pk)
void unpack_pk(uint8_t rho[MLDSA_SEEDBYTES], polyveck *t1,
               const uint8_t pk[CRYPTO_PUBLICKEYBYTES])
__contract__(
  requires(memory_no_alias(pk, CRYPTO_PUBLICKEYBYTES))
  requires(memory_no_alias(rho, MLDSA_SEEDBYTES))
  requires(memory_no_alias(t1, sizeof(polyveck)))
  assigns(object_whole(rho))
  assigns(object_whole(t1))
  ensures(forall(k0, 0, MLDSA_K,
    array_bound(t1->vec[k0].coeffs, 0, MLDSA_N, 0, 1 << 10)))
);


#define unpack_sk MLD_NAMESPACE(unpack_sk)
void unpack_sk(uint8_t rho[MLDSA_SEEDBYTES], uint8_t tr[MLDSA_TRBYTES],
               uint8_t key[MLDSA_SEEDBYTES], polyveck *t0, polyvecl *s1,
               polyveck *s2, const uint8_t sk[CRYPTO_SECRETKEYBYTES])
__contract__(
  requires(memory_no_alias(rho, MLDSA_SEEDBYTES))
  requires(memory_no_alias(tr, MLDSA_TRBYTES))
  requires(memory_no_alias(key, MLDSA_SEEDBYTES))
  requires(memory_no_alias(t0, sizeof(polyveck)))
  requires(memory_no_alias(s1, sizeof(polyvecl)))
  requires(memory_no_alias(s2, sizeof(polyveck)))
  requires(memory_no_alias(sk, CRYPTO_SECRETKEYBYTES))
  assigns(object_whole(rho))
  assigns(object_whole(tr))
  assigns(object_whole(key))
  assigns(object_whole(t0))
  assigns(object_whole(s1))
  assigns(object_whole(s2))
  ensures(forall(k0, 0, MLDSA_K,
    array_bound(t0->vec[k0].coeffs, 0, MLDSA_N, -(1<<(MLDSA_D-1)) + 1, (1<<(MLDSA_D-1)) + 1)))
  ensures(forall(k1, 0, MLDSA_L,
    array_bound(s1->vec[k1].coeffs, 0, MLDSA_N, MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1)))
  ensures(forall(k2, 0, MLDSA_K,
    array_bound(s2->vec[k2].coeffs, 0, MLDSA_N, MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1)))
);

#define unpack_sig MLD_NAMESPACE(unpack_sig)
int unpack_sig(uint8_t c[MLDSA_CTILDEBYTES], polyvecl *z, polyveck *h,
               const uint8_t sig[CRYPTO_BYTES]);

#endif
