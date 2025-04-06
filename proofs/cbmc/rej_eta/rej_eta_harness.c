// Copyright (c) 2025 The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include "poly.h"

unsigned rej_eta(int32_t *a, unsigned int len, const uint8_t *buf,
                 unsigned int buflen);

void harness(void)
{
  int32_t *a;
  unsigned int len;
  const uint8_t *buf;
  unsigned int buflen;

  rej_eta(a, len, buf, buflen);
}
