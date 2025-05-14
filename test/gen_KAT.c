/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../mldsa/api.h"
#include "notrandombytes/notrandombytes.h"

#define MAXMLEN 2048
#define CTXLEN 0

static void print_hex(const uint8_t *data, size_t size)
{
  size_t i;
  for (i = 0; i < size; i++)
  {
    printf("%02x", data[i]);
  }
  printf("\n");
}

int main(void)
{
  unsigned i, j;
  int rc;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sm[MAXMLEN + CRYPTO_BYTES];
  uint8_t s[CRYPTO_BYTES];
  uint8_t m[MAXMLEN];
  uint8_t m2[MAXMLEN + CRYPTO_BYTES];
  size_t smlen;
  size_t slen;
  size_t mlen;

  for (i = 0; i < MAXMLEN; i = (i == 0) ? i + 1 : i << 2)
  {
    randombytes(m, i);


    crypto_sign_keypair(pk, sk);

    print_hex(pk, CRYPTO_PUBLICKEYBYTES);
    print_hex(sk, CRYPTO_SECRETKEYBYTES);

    crypto_sign(sm, &smlen, m, i, NULL, CTXLEN, sk);
    crypto_sign_signature(s, &slen, m, i, NULL, CTXLEN, sk);

    print_hex(sm, smlen);
    print_hex(s, slen);

    rc = crypto_sign_open(m2, &mlen, sm, smlen, NULL, CTXLEN, pk);
    rc |= crypto_sign_verify(s, slen, m, i, NULL, CTXLEN, pk);

    if (rc)
    {
      printf("ERROR: signature verification failed\n");
      return -1;
    }
    for (j = 0; j < i; j++)
    {
      if (m2[j] != m[j])
      {
        printf("ERROR: message recovery failed\n");
        return -1;
      }
    }
  }
  return 0;
}
