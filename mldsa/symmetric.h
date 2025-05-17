/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLD_SYMMETRIC_H
#define MLD_SYMMETRIC_H

#include <stdint.h>
#include "cbmc.h"
#include "common.h"

#include "fips202/fips202.h"

typedef keccak_state stream256_state;

#define mldsa_shake256_stream_init MLD_NAMESPACE(mldsa_shake256_stream_init)
void mldsa_shake256_stream_init(keccak_state *state,
                                const uint8_t seed[MLDSA_CRHBYTES],
                                uint16_t nonce)
__contract__(
  requires(memory_no_alias(state, sizeof(keccak_state)))
  requires(memory_no_alias(seed, MLDSA_CRHBYTES))
  assigns(memory_slice(state, sizeof(keccak_state)))
  ensures(state->pos <= SHAKE256_RATE)
);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream256_init(STATE, SEED, NONCE) \
  mldsa_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)

#define mld_xof_ctx keccak_state
#define mld_xof_init(CTX) shake128_init(CTX)
#define mld_xof_absorb(CTX, IN, INBYTES) \
  do                                     \
  {                                      \
    shake128_absorb(CTX, IN, INBYTES);   \
    shake128_finalize(CTX);              \
  } while (0)


#define mld_xof_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)

#define mld_xof_x4_ctx mld_shake128x4ctx
#define mld_xof_x4_init(CTX) mld_shake128x4_init((CTX))
#define mld_xof_x4_absorb(CTX, IN, INBYTES)                             \
  mld_shake128x4_absorb_once((CTX), (IN)[0], (IN)[1], (IN)[2], (IN)[3], \
                             (INBYTES))
#define mld_xof_x4_squeezeblocks(BUF, NBLOCKS, CTX)                    \
  mld_shake128x4_squeezeblocks((BUF)[0], (BUF)[1], (BUF)[2], (BUF)[3], \
                               (NBLOCKS), (CTX))
#define mld_xof_x4_release(CTX) mld_shake128x4_release((CTX))

#endif /* !MLD_SYMMETRIC_H */
