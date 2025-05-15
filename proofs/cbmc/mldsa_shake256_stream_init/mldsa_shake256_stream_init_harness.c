// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include "params.h"
#include "symmetric.h"

void harness(void)
{
  keccak_state *s;
  const uint8_t *seed;
  uint16_t nonce;

  mldsa_shake256_stream_init(s, seed, nonce);
}
