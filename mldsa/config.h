/*
 * Copyright (c) 2025 The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef MLD_CONFIG_H
#define MLD_CONFIG_H

#define MLD_RANDOMIZED_SIGNING

#ifndef MLDSA_MODE
#define MLDSA_MODE 2
#endif

#if MLDSA_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2"
#define MLD_NAMESPACETOP MLD_44_ref
#define MLD_NAMESPACE(s) MLD_44_ref_##s
#elif MLDSA_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define MLD_NAMESPACETOP MLD_65_ref
#define MLD_NAMESPACE(s) MLD_65_ref_##s
#elif MLDSA_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define MLD_NAMESPACETOP MLD_87_ref
#define MLD_NAMESPACE(s) MLD_87_ref_##s
#endif

/******************************************************************************
 * Name:        MLD_CONFIG_ARITH_BACKEND_FILE
 *
 * Description: The arithmetic backend to use.
 *
 *              If MLD_CONFIG_USE_NATIVE_BACKEND_ARITH is unset, this option
 *              is ignored.
 *
 *              If MLD_CONFIG_USE_NATIVE_BACKEND_ARITH is set, this option must
 *              either be undefined or the filename of an arithmetic backend.
 *              If unset, the default backend will be used.
 *
 *              This can be set using CFLAGS.
 *
 *****************************************************************************/
#if defined(MLD_CONFIG_USE_NATIVE_BACKEND_ARITH) && \
    !defined(MLD_CONFIG_ARITH_BACKEND_FILE)
#define MLD_CONFIG_ARITH_BACKEND_FILE "native/meta.h"
#endif

#endif /* !MLD_CONFIG_H */
