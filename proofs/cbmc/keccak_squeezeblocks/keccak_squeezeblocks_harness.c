// Copyright (c) 2025 The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include "fips202/fips202.h"

extern void keccak_squeezeblocks(uint8_t *out, size_t nblocks,
                                 uint64_t s[MLD_KECCAK_LANES], unsigned int r);

void harness(void)
{
  uint8_t *out;
  size_t nblocks;
  uint64_t *s;
  unsigned int r;

  keccak_squeezeblocks(out, nblocks, s, r);
}
