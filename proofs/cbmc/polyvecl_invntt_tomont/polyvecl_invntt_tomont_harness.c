// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

void harness(void)
{
  polyvecl *v;
  polyvecl_invntt_tomont(v);
}
