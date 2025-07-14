/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLD_CONFIG_H
#define MLD_CONFIG_H

#define MLD_RANDOMIZED_SIGNING

#ifndef MLDSA_MODE
#define MLDSA_MODE 2
#endif

#if MLDSA_MODE == 2
#define MLD_NAMESPACETOP MLD_44_ref
#define MLD_NAMESPACE(s) MLD_44_ref_##s
#elif MLDSA_MODE == 3
#define MLD_NAMESPACETOP MLD_65_ref
#define MLD_NAMESPACE(s) MLD_65_ref_##s
#elif MLDSA_MODE == 5
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

/******************************************************************************
 * Name:        MLD_CONFIG_FIPS202_BACKEND_FILE
 *
 * Description: The FIPS-202 backend to use.
 *
 *              If MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202 is set, this option
 *              must either be undefined or the filename of a FIPS202 backend.
 *              If unset, the default backend will be used.
 *
 *              This can be set using CFLAGS.
 *
 *****************************************************************************/
#if defined(MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202) && \
    !defined(MLD_CONFIG_FIPS202_BACKEND_FILE)
#define MLD_CONFIG_FIPS202_BACKEND_FILE "fips202/native/auto.h"
#endif

#endif /* !MLD_CONFIG_H */
