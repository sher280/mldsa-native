// Copyright (c) 2025 The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include "fips202/fips202.h"

void harness(void)
{
  uint8_t *out;
  size_t outlen;
  const uint8_t *in;
  size_t inlen;

  shake128(out, outlen, in, inlen);
}
