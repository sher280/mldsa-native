#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>

#define pqcrystals_dilithium2_PUBLICKEYBYTES 1312
#define pqcrystals_dilithium2_SECRETKEYBYTES 2560
#define pqcrystals_dilithium2_BYTES 2420

#define pqcrystals_dilithium2_ref_PUBLICKEYBYTES \
  pqcrystals_dilithium2_PUBLICKEYBYTES
#define pqcrystals_dilithium2_ref_SECRETKEYBYTES \
  pqcrystals_dilithium2_SECRETKEYBYTES
#define pqcrystals_dilithium2_ref_BYTES pqcrystals_dilithium2_BYTES

int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium2_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);

int pqcrystals_dilithium2_ref(uint8_t *sm, size_t *smlen, const uint8_t *m,
                              size_t mlen, const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk);

int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium2_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                                   size_t smlen, const uint8_t *ctx,
                                   size_t ctxlen, const uint8_t *pk);

#define pqcrystals_dilithium3_PUBLICKEYBYTES 1952
#define pqcrystals_dilithium3_SECRETKEYBYTES 4032
#define pqcrystals_dilithium3_BYTES 3309

#define pqcrystals_dilithium3_ref_PUBLICKEYBYTES \
  pqcrystals_dilithium3_PUBLICKEYBYTES
#define pqcrystals_dilithium3_ref_SECRETKEYBYTES \
  pqcrystals_dilithium3_SECRETKEYBYTES
#define pqcrystals_dilithium3_ref_BYTES pqcrystals_dilithium3_BYTES

int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);

int pqcrystals_dilithium3_ref(uint8_t *sm, size_t *smlen, const uint8_t *m,
                              size_t mlen, const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk);

int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium3_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                                   size_t smlen, const uint8_t *ctx,
                                   size_t ctxlen, const uint8_t *pk);

#define pqcrystals_dilithium5_PUBLICKEYBYTES 2592
#define pqcrystals_dilithium5_SECRETKEYBYTES 4896
#define pqcrystals_dilithium5_BYTES 4627

#define pqcrystals_dilithium5_ref_PUBLICKEYBYTES \
  pqcrystals_dilithium5_PUBLICKEYBYTES
#define pqcrystals_dilithium5_ref_SECRETKEYBYTES \
  pqcrystals_dilithium5_SECRETKEYBYTES
#define pqcrystals_dilithium5_ref_BYTES pqcrystals_dilithium5_BYTES

int pqcrystals_dilithium5_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);

int pqcrystals_dilithium5_ref(uint8_t *sm, size_t *smlen, const uint8_t *m,
                              size_t mlen, const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk);

int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium5_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm,
                                   size_t smlen, const uint8_t *ctx,
                                   size_t ctxlen, const uint8_t *pk);

#if DILITHIUM_MODE == 2
#define CRYPTO_PUBLICKEYBYTES pqcrystals_dilithium2_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES pqcrystals_dilithium2_SECRETKEYBYTES
#define CRYPTO_BYTES pqcrystals_dilithium2_BYTES
#define crypto_sign_keypair pqcrystals_dilithium2_ref_keypair
#define crypto_sign_signature pqcrystals_dilithium2_ref_signature
#define crypto_sign pqcrystals_dilithium2_ref
#define crypto_sign_verify pqcrystals_dilithium2_ref_verify
#define crypto_sign_open pqcrystals_dilithium2_ref_open
#elif DILITHIUM_MODE == 3
#define CRYPTO_PUBLICKEYBYTES pqcrystals_dilithium3_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES pqcrystals_dilithium3_SECRETKEYBYTES
#define CRYPTO_BYTES pqcrystals_dilithium3_BYTES
#define crypto_sign_keypair pqcrystals_dilithium3_ref_keypair
#define crypto_sign_signature pqcrystals_dilithium3_ref_signature
#define crypto_sign pqcrystals_dilithium3_ref
#define crypto_sign_verify pqcrystals_dilithium3_ref_verify
#define crypto_sign_open pqcrystals_dilithium3_ref_open
#elif DILITHIUM_MODE == 5
#define CRYPTO_PUBLICKEYBYTES pqcrystals_dilithium5_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES pqcrystals_dilithium5_SECRETKEYBYTES
#define CRYPTO_BYTES pqcrystals_dilithium5_BYTES
#define crypto_sign_keypair pqcrystals_dilithium5_ref_keypair
#define crypto_sign_signature pqcrystals_dilithium5_ref_signature
#define crypto_sign pqcrystals_dilithium5_ref
#define crypto_sign_verify pqcrystals_dilithium5_ref_verify
#define crypto_sign_open pqcrystals_dilithium5_ref_open
#endif


#endif
