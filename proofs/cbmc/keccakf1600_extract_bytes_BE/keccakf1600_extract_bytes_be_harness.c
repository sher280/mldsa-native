// Copyright (c) 2025 The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include "fips202/fips202.h"

extern void keccakf1600_extract_bytes(uint64_t *state, unsigned char *data,
                                      unsigned offset, unsigned length);

void harness(void)
{
  uint64_t *state;
  unsigned char *data;
  unsigned offset;
  unsigned length;

  keccakf1600_extract_bytes(state, data, offset, length);
}
