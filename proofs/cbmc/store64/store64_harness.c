// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include "fips202/fips202.h"

extern void store64(uint8_t x[8], uint64_t u);

void harness(void)
{
  uint8_t *x;
  uint64_t u;
  store64(x, u);
}
