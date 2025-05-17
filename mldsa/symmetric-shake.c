/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#include <stdint.h>
#include "fips202/fips202.h"
#include "params.h"
#include "symmetric.h"


void mldsa_shake256_stream_init(keccak_state *state,
                                const uint8_t seed[MLDSA_CRHBYTES],
                                uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce & 0xFF;
  t[1] = nonce >> 8;

  shake256_init(state);
  shake256_absorb(state, seed, MLDSA_CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}
