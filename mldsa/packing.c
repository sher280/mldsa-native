/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "packing.h"
#include <string.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"

/*************************************************
 * Name:        pack_pk
 *
 * Description: Bit-pack public key pk = (rho, t1).
 *
 * Arguments:   - uint8_t pk[]: output byte array
 *              - const uint8_t rho[]: byte array containing rho
 *              - const polyveck *t1: pointer to vector t1
 **************************************************/
void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES], const polyveck *t1)
{
  unsigned int i;

  memcpy(pk, rho, MLDSA_SEEDBYTES);
  pk += MLDSA_SEEDBYTES;

  for (i = 0; i < MLDSA_K; ++i)
  {
    polyt1_pack(pk + i * MLDSA_POLYT1_PACKEDBYTES, &t1->vec[i]);
  }
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: Unpack public key pk = (rho, t1).
 *
 * Arguments:   - const uint8_t rho[]: output byte array for rho
 *              - const polyveck *t1: pointer to output vector t1
 *              - uint8_t pk[]: byte array containing bit-packed pk
 **************************************************/
void unpack_pk(uint8_t rho[MLDSA_SEEDBYTES], polyveck *t1,
               const uint8_t pk[CRYPTO_PUBLICKEYBYTES])
{
  unsigned int i;

  memcpy(rho, pk, MLDSA_SEEDBYTES);
  pk += MLDSA_SEEDBYTES;

  for (i = 0; i < MLDSA_K; ++i)
    polyt1_unpack(&t1->vec[i], pk + i * MLDSA_POLYT1_PACKEDBYTES);
}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * Arguments:   - uint8_t sk[]: output byte array
 *              - const uint8_t rho[]: byte array containing rho
 *              - const uint8_t tr[]: byte array containing tr
 *              - const uint8_t key[]: byte array containing key
 *              - const polyveck *t0: pointer to vector t0
 *              - const polyvecl *s1: pointer to vector s1
 *              - const polyveck *s2: pointer to vector s2
 **************************************************/
void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES],
             const uint8_t tr[MLDSA_TRBYTES],
             const uint8_t key[MLDSA_SEEDBYTES], const polyveck *t0,
             const polyvecl *s1, const polyveck *s2)
{
  memcpy(sk, rho, MLDSA_SEEDBYTES);
  sk += MLDSA_SEEDBYTES;

  memcpy(sk, key, MLDSA_SEEDBYTES);
  sk += MLDSA_SEEDBYTES;

  memcpy(sk, tr, MLDSA_TRBYTES);
  sk += MLDSA_TRBYTES;

  polyvecl_pack_eta(sk, s1);
  sk += MLDSA_L * MLDSA_POLYETA_PACKEDBYTES;

  polyveck_pack_eta(sk, s2);
  sk += MLDSA_K * MLDSA_POLYETA_PACKEDBYTES;

  polyveck_pack_t0(sk, t0);
}

/*************************************************
 * Name:        unpack_sk
 *
 * Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * Arguments:   - const uint8_t rho[]: output byte array for rho
 *              - const uint8_t tr[]: output byte array for tr
 *              - const uint8_t key[]: output byte array for key
 *              - const polyveck *t0: pointer to output vector t0
 *              - const polyvecl *s1: pointer to output vector s1
 *              - const polyveck *s2: pointer to output vector s2
 *              - uint8_t sk[]: byte array containing bit-packed sk
 **************************************************/
void unpack_sk(uint8_t rho[MLDSA_SEEDBYTES], uint8_t tr[MLDSA_TRBYTES],
               uint8_t key[MLDSA_SEEDBYTES], polyveck *t0, polyvecl *s1,
               polyveck *s2, const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  memcpy(rho, sk, MLDSA_SEEDBYTES);
  sk += MLDSA_SEEDBYTES;

  memcpy(key, sk, MLDSA_SEEDBYTES);
  sk += MLDSA_SEEDBYTES;

  memcpy(tr, sk, MLDSA_TRBYTES);
  sk += MLDSA_TRBYTES;

  polyvecl_unpack_eta(s1, sk);
  sk += MLDSA_L * MLDSA_POLYETA_PACKEDBYTES;

  polyveck_unpack_eta(s2, sk);
  sk += MLDSA_K * MLDSA_POLYETA_PACKEDBYTES;

  polyveck_unpack_t0(t0, sk);
}

/*************************************************
 * Name:        pack_sig
 *
 * Description: Bit-pack signature sig = (c, z, h).
 *
 * Arguments:   - uint8_t sig[]: output byte array
 *              - const uint8_t *c:  pointer to challenge hash length
 *                                   MLDSA_SEEDBYTES
 *              - const polyvecl *z: pointer to vector z
 *              - const polyveck *h: pointer to hint vector h
 *              - const unsigned int number_of_hints: total
 *                                   hints in *h
 *
 * Note that the number_of_hints argument is not present
 * in the reference implementation. It is added here to ease
 * proof of type safety.
 **************************************************/
void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[MLDSA_CTILDEBYTES],
              const polyvecl *z, const polyveck *h,
              const unsigned int number_of_hints)
{
  unsigned int i, j, k;

  memcpy(sig, c, MLDSA_CTILDEBYTES);
  sig += MLDSA_CTILDEBYTES;

  polyvecl_pack_z(sig, z);
  sig += MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;

  /* Encode hints h */

  /* The final section of sig[] is MLDSA_POLYVECH_PACKEDBYTES long, where
   * MLDSA_POLYVECH_PACKEDBYTES = MLDSA_OMEGA + MLDSA_K
   *
   * The first OMEGA bytes record the index numbers of the coefficients
   * that are not equal to 0
   *
   * The final K bytes record a running tally of the number of hints
   * coming from each of the K polynomials in h.
   *
   * The pre-condition tells us that number_of_hints <= OMEGA, so some
   * bytes may not be written, so we initialize all of them to zero
   * to start.
   */
  memset(sig, 0, MLDSA_POLYVECH_PACKEDBYTES);

  k = 0;
  /* For each polynomial in h... */
  for (i = 0; i < MLDSA_K; ++i)
  __loop__(
    assigns(i, j, k, memory_slice(sig, MLDSA_POLYVECH_PACKEDBYTES))
    invariant(i <= MLDSA_K)
    invariant(k <= number_of_hints)
    invariant(number_of_hints <= MLDSA_OMEGA)
  )
  {
    /* For each coefficient in that polynomial, record it as as hint */
    /* if its value is not zero */
    for (j = 0; j < MLDSA_N; ++j)
    __loop__(
      assigns(j, k, memory_slice(sig, MLDSA_POLYVECH_PACKEDBYTES))
      invariant(i <= MLDSA_K)
      invariant(j <= MLDSA_N)
      invariant(k <= number_of_hints)
      invariant(number_of_hints <= MLDSA_OMEGA)
    )
    {
      /* The reference implementation implicitly relies on the total */
      /* number of hints being less than OMEGA, assuming h is valid. */
      /* In mldsa-native, we check this explicitly to ease proof of  */
      /* type safety.                                                */
      if (h->vec[i].coeffs[j] != 0 && k < number_of_hints)
      {
        /* The enclosing if condition AND the loop invariant infer  */
        /* that k < MLDSA_OMEGA, so writing to sig[k] is safe and k */
        /* can be incremented.                                      */
        sig[k++] = j;
      }
    }
    /* Having recorded all the hints for this polynomial, also   */
    /* record the running tally into the correct "slot" for that */
    /* coefficient in the final K bytes                          */
    sig[MLDSA_OMEGA + i] = k;
  }
}

/*************************************************
 * Name:        unpack_sig
 *
 * Description: Unpack signature sig = (c, z, h).
 *
 * Arguments:   - uint8_t *c: pointer to output challenge hash
 *              - polyvecl *z: pointer to output vector z
 *              - polyveck *h: pointer to output hint vector h
 *              - const uint8_t sig[]: byte array containing
 *                bit-packed signature
 *
 * Returns 1 in case of malformed signature; otherwise 0.
 **************************************************/
int unpack_sig(uint8_t c[MLDSA_CTILDEBYTES], polyvecl *z, polyveck *h,
               const uint8_t sig[CRYPTO_BYTES])
{
  unsigned int i, j, k;

  for (i = 0; i < MLDSA_CTILDEBYTES; ++i)
    c[i] = sig[i];
  sig += MLDSA_CTILDEBYTES;

  for (i = 0; i < MLDSA_L; ++i)
    polyz_unpack(&z->vec[i], sig + i * MLDSA_POLYZ_PACKEDBYTES);
  sig += MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;

  /* Decode h */
  k = 0;
  for (i = 0; i < MLDSA_K; ++i)
  {
    for (j = 0; j < MLDSA_N; ++j)
      h->vec[i].coeffs[j] = 0;

    if (sig[MLDSA_OMEGA + i] < k || sig[MLDSA_OMEGA + i] > MLDSA_OMEGA)
      return 1;

    for (j = k; j < sig[MLDSA_OMEGA + i]; ++j)
    {
      /* Coefficients are ordered for strong unforgeability */
      if (j > k && sig[j] <= sig[j - 1])
        return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[MLDSA_OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for (j = k; j < MLDSA_OMEGA; ++j)
    if (sig[j])
      return 1;

  return 0;
}
