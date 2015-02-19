#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

#define CF_SHA1_HASHSZ 20
#define CF_SHA1_BLOCKSZ 64

typedef struct
{
  uint32_t H[5];                    /* State. */
  uint8_t partial[CF_SHA1_BLOCKSZ]; /* Partial block of input. */
  uint32_t blocks;                  /* Number of full blocks processed into H. */
  size_t npartial;                  /* Number of bytes in prefix of partial. */
} cf_sha1_context;

extern void cf_sha1_init(cf_sha1_context *ctx);
extern void cf_sha1_update(cf_sha1_context *ctx, const void *data, size_t nbytes);
extern void cf_sha1_digest(const cf_sha1_context *ctx, uint8_t hash[CF_SHA1_HASHSZ]);
extern void cf_sha1_digest_final(cf_sha1_context *ctx, uint8_t hash[CF_SHA1_HASHSZ]);

extern const cf_chash cf_sha1;

#endif
