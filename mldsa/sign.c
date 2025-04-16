/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <string.h>

#include "cbmc.h"
#include "fips202/fips202.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "sign.h"
#include "symmetric.h"

int crypto_sign_keypair_internal(uint8_t *pk, uint8_t *sk,
                                 const uint8_t seed[MLDSA_SEEDBYTES])
{
  uint8_t seedbuf[2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES];
  uint8_t tr[MLDSA_TRBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[MLDSA_K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  memcpy(seedbuf, seed, MLDSA_SEEDBYTES);
  seedbuf[MLDSA_SEEDBYTES + 0] = MLDSA_K;
  seedbuf[MLDSA_SEEDBYTES + 1] = MLDSA_L;
  shake256(seedbuf, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES, seedbuf,
           MLDSA_SEEDBYTES + 2);
  rho = seedbuf;
  rhoprime = rho + MLDSA_SEEDBYTES;
  key = rhoprime + MLDSA_CRHBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, MLDSA_L);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(&t1, &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, MLDSA_TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
  return 0;
}

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
  uint8_t seed[MLDSA_SEEDBYTES];
  randombytes(seed, MLDSA_SEEDBYTES);
  return crypto_sign_keypair_internal(pk, sk, seed);
}

int crypto_sign_signature_internal(uint8_t *sig, size_t *siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen,
                                   const uint8_t rnd[MLDSA_RNDBYTES],
                                   const uint8_t *sk, int externalmu)
{
  unsigned int n;
  uint8_t seedbuf[2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2 * MLDSA_CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[MLDSA_K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + MLDSA_SEEDBYTES;
  key = tr + MLDSA_TRBYTES;
  mu = key + MLDSA_SEEDBYTES;
  rhoprime = mu + MLDSA_CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  if (!externalmu)
  {
    /* Compute mu = CRH(tr, pre, msg) */
    shake256_init(&state);
    shake256_absorb(&state, tr, MLDSA_TRBYTES);
    shake256_absorb(&state, pre, prelen);
    shake256_absorb(&state, m, mlen);
    shake256_finalize(&state);
    shake256_squeeze(mu, MLDSA_CRHBYTES, &state);
  }
  else
  {
    /* mu has been provided directly */
    memcpy(mu, m, MLDSA_CRHBYTES);
  }

  /* Compute rhoprime = CRH(key, rnd, mu) */
  shake256_init(&state);
  shake256_absorb(&state, key, MLDSA_SEEDBYTES);
  shake256_absorb(&state, rnd, MLDSA_RNDBYTES);
  shake256_absorb(&state, mu, MLDSA_CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(rhoprime, MLDSA_CRHBYTES, &state);

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, MLDSA_CRHBYTES);
  shake256_absorb(&state, sig, MLDSA_K * MLDSA_POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, MLDSA_CTILDEBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if (polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA))
  {
    goto rej;
  }

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if (polyveck_chknorm(&w0, MLDSA_GAMMA2 - MLDSA_BETA))
  {
    goto rej;
  }

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if (polyveck_chknorm(&h, MLDSA_GAMMA2))
  {
    goto rej;
  }

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if (n > MLDSA_OMEGA)
  {
    goto rej;
  }

  /* Write signature */
  pack_sig(sig, sig, &z, &h, n);
  *siglen = CRYPTO_BYTES;
  return 0;
}

int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                          size_t mlen, const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *sk)
{
  size_t i;
  uint8_t pre[257];
  uint8_t rnd[MLDSA_RNDBYTES];

  if (ctxlen > 255)
  {
    return -1;
  }

  /* Prepare pre = (0, ctxlen, ctx) */
  pre[0] = 0;
  pre[1] = ctxlen;
  for (i = 0; i < ctxlen; i++)
  {
    pre[2 + i] = ctx[i];
  }

#ifdef MLD_RANDOMIZED_SIGNING
  randombytes(rnd, MLDSA_RNDBYTES);
#else
  for (i = 0; i < MLDSA_RNDBYTES; i++)
  {
    rnd[i] = 0;
  }
#endif /* !MLD_RANDOMIZED_SIGNING */

  crypto_sign_signature_internal(sig, siglen, m, mlen, pre, 2 + ctxlen, rnd, sk,
                                 0);
  return 0;
}

int crypto_sign_signature_extmu(uint8_t *sig, size_t *siglen,
                                const uint8_t mu[MLDSA_CRHBYTES],
                                const uint8_t *sk)
{
  uint8_t rnd[MLDSA_RNDBYTES];

#ifdef MLD_RANDOMIZED_SIGNING
  randombytes(rnd, MLDSA_RNDBYTES);
#else
  size_t i;
  for (i = 0; i < MLDSA_RNDBYTES; i++)
  {
    rnd[i] = 0;
  }
#endif /* !MLD_RANDOMIZED_SIGNING */

  crypto_sign_signature_internal(sig, siglen, mu, 0, NULL, 0, rnd, sk, 1);
  return 0;
}

int crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen, const uint8_t *sk)
{
  int ret;
  size_t i;

  for (i = 0; i < mlen; ++i)
  {
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  }
  ret = crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, ctx, ctxlen,
                              sk);
  *smlen += mlen;
  return ret;
}

int crypto_sign_verify_internal(const uint8_t *sig, size_t siglen,
                                const uint8_t *m, size_t mlen,
                                const uint8_t *pre, size_t prelen,
                                const uint8_t *pk, int externalmu)
{
  unsigned int i;
  uint8_t buf[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES];
  uint8_t rho[MLDSA_SEEDBYTES];
  uint8_t mu[MLDSA_CRHBYTES];
  uint8_t c[MLDSA_CTILDEBYTES];
  uint8_t c2[MLDSA_CTILDEBYTES];
  poly cp;
  polyvecl mat[MLDSA_K], z;
  polyveck t1, w1, h;
  keccak_state state;

  if (siglen != CRYPTO_BYTES)
  {
    return -1;
  }

  unpack_pk(rho, &t1, pk);
  if (unpack_sig(c, &z, &h, sig))
  {
    return -1;
  }
  if (polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA))
  {
    return -1;
  }

  if (!externalmu)
  {
    /* Compute CRH(H(rho, t1), pre, msg) */
    shake256(mu, MLDSA_TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    shake256_init(&state);
    shake256_absorb(&state, mu, MLDSA_TRBYTES);
    shake256_absorb(&state, pre, prelen);
    shake256_absorb(&state, m, mlen);
    shake256_finalize(&state);
    shake256_squeeze(mu, MLDSA_CRHBYTES, &state);
  }
  else
  {
    /* mu has been provided directly */
    memcpy(mu, m, MLDSA_CRHBYTES);
  }

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, MLDSA_CRHBYTES);
  shake256_absorb(&state, buf, MLDSA_K * MLDSA_POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, MLDSA_CTILDEBYTES, &state);
  for (i = 0; i < MLDSA_CTILDEBYTES; ++i)
  {
    if (c[i] != c2[i])
    {
      return -1;
    }
  }

  return 0;
}

int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                       size_t mlen, const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk)
{
  size_t i;
  uint8_t pre[257];

  if (ctxlen > 255)
  {
    return -1;
  }

  pre[0] = 0;
  pre[1] = ctxlen;
  for (i = 0; i < ctxlen; i++)
  {
    pre[2 + i] = ctx[i];
  }

  return crypto_sign_verify_internal(sig, siglen, m, mlen, pre, 2 + ctxlen, pk,
                                     0);
}

int crypto_sign_verify_extmu(const uint8_t *sig, size_t siglen,
                             const uint8_t mu[MLDSA_CRHBYTES],
                             const uint8_t *pk)
{
  return crypto_sign_verify_internal(sig, siglen, mu, 0, NULL, 0, pk, 1);
}

int crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen,
                     const uint8_t *ctx, size_t ctxlen, const uint8_t *pk)
{
  size_t i;

  if (smlen < CRYPTO_BYTES)
  {
    goto badsig;
  }

  *mlen = smlen - CRYPTO_BYTES;
  if (crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, ctx,
                         ctxlen, pk))
  {
    goto badsig;
  }
  else
  {
    /* All good, copy msg, return 0 */
    for (i = 0; i < *mlen; ++i)
    {
      m[i] = sm[CRYPTO_BYTES + i];
    }
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = 0;
  for (i = 0; i < smlen; ++i)
  {
    m[i] = 0;
  }

  return -1;
}
