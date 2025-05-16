// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

#include "fips202/fips202.h"

extern void keccak_absorb_once(uint64_t s[MLD_KECCAK_LANES],
                               const unsigned int r, const uint8_t *in,
                               size_t inlen, uint8_t p);

void harness(void)
{
  uint64_t *s;
  const unsigned int r;
  const uint8_t *in;
  size_t inlen;
  uint8_t p;

  keccak_absorb_once(s, r, in, inlen, p);
}
