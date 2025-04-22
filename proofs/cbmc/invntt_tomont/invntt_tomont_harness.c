// Copyright (c) 2025 The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include "ntt.h"
#include "params.h"

void invntt_tomont(int32_t a[MLDSA_N]);

void harness(void)
{
  int32_t *a;
  invntt_tomont(a);
}
