// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include "polyvec.h"

void harness(void)
{
  polyveck *a, *b;
  poly *c;
  polyveck_pointwise_poly_montgomery(a, c, b);
}
