// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

#include "poly.h"

void harness(void)
{
  poly *r0;
  poly *r1;
  poly *r2;
  poly *r3;
  uint8_t(*seed)[MLD_ALIGN_UP(MLDSA_SEEDBYTES + 2)];

  poly_uniform_4x(r0, r1, r2, r3, seed);
}
