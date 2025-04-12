// Copyright (c) 2025 The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include "poly.h"

void harness(void)
{
  poly *a, *b, *c;
  poly_pointwise_montgomery(c, a, b);
}
