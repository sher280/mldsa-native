/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NISTRNG_H
#define NISTRNG_H

#include "../../mldsa/randombytes.h"
#include "aes.h"

void nist_kat_init(
    unsigned char entropy_input[AES256_KEYBYTES + AES_BLOCKBYTES],
    const unsigned char
        personalization_string[AES256_KEYBYTES + AES_BLOCKBYTES],
    int security_strength);

#endif
