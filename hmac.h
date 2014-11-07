#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

/* Incremental interface context. */
typedef struct
{
  const cf_chash *hash;
  cf_chash_ctx inner;
  cf_chash_ctx outer;
} cf_hmac_ctx;

/* Set up ctx for computing a HMAC using the given hash and key. */
void cf_hmac_init(cf_hmac_ctx *ctx,
                  const cf_chash *hash,
                  const uint8_t *key, size_t nkey);

/* Input data. */
void cf_hmac_update(cf_hmac_ctx *ctx,
                    const void *data, size_t ndata);

/* Finish and compute HMAC.
 * ctx->hash->hashsz bytes are written to out. */
void cf_hmac_finish(cf_hmac_ctx *ctx, uint8_t *out);

/* One shot interface: compute HMAC_hash(key, msg), writing the
 * answer (which is hash->hashsz long) to out. 
 * 
 * This function does not fail. */
void cf_hmac(const uint8_t *key, size_t nkey,
             const uint8_t *msg, size_t nmsg,
             uint8_t *out,
             const cf_chash *hash);

#endif
