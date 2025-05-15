// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

#include "fips202/fips202.h"

extern uint64_t load64(const uint8_t x[8]);

void harness(void)
{
  const uint8_t *x;
  load64(x);
}
