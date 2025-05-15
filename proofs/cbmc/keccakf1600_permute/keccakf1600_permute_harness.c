// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

#include "fips202/fips202.h"

extern void KeccakF1600_StatePermute(uint64_t state[25]);

void harness(void)
{
  uint64_t *a;

  KeccakF1600_StatePermute(a);
}
