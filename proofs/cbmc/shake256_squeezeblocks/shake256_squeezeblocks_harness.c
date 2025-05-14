// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include "fips202/fips202.h"

void harness(void)
{
  uint8_t *out;
  size_t nblocks;
  keccak_state *state;

  shake256_squeezeblocks(out, nblocks, state);
}
