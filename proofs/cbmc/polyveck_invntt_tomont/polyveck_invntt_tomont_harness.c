// Copyright (c) 2025 The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

void harness(void)
{
  polyveck *v;
  polyveck_invntt_tomont(v);
}
