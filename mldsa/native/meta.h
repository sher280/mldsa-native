/*
 * Copyright (c) 2024-2025 The mlkem-native project authors
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLD_NATIVE_META_H
#define MLD_NATIVE_META_H

/*
 * Default arithmetic backend
 */
#include "../sys.h"

#ifdef MLD_SYS_AARCH64
#include "aarch64/meta.h"
#endif

/*
#ifdef MLD_SYS_X86_64_AVX2
#include "x86_64/meta.h"
#endif
*/

#endif /* !MLD_NATIVE_META_H */
