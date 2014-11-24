#ifndef SHA2_H
#define SHA2_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

#define CF_SHA224_HASHSZ 28
#define CF_SHA224_BLOCKSZ 64

#define CF_SHA256_HASHSZ 32
#define CF_SHA256_BLOCKSZ 64

typedef struct
{
  uint32_t H[8];                      /* State. */
  uint8_t partial[CF_SHA256_BLOCKSZ]; /* Partial block of input. */
  uint32_t blocks;                    /* Number of full blocks processed into H. */
  size_t npartial;                    /* Number of bytes in prefix of partial. */
} cf_sha256_context;

extern void cf_sha256_init(cf_sha256_context *ctx);
extern void cf_sha256_update(cf_sha256_context *ctx, const void *data, size_t nbytes);
extern void cf_sha256_final(const cf_sha256_context *ctx, uint8_t hash[CF_SHA256_HASHSZ]);

/* nb. SHA224 uses SHA256's underlying types. */
extern void cf_sha224_init(cf_sha256_context *ctx);
extern void cf_sha224_update(cf_sha256_context *ctx, const void *data, size_t nbytes);
extern void cf_sha224_final(const cf_sha256_context *ctx, uint8_t hash[CF_SHA224_HASHSZ]);

extern const cf_chash cf_sha256;
extern const cf_chash cf_sha224;

#define CF_SHA384_HASHSZ 48
#define CF_SHA384_BLOCKSZ 128

#define CF_SHA512_HASHSZ 64
#define CF_SHA512_BLOCKSZ 128

typedef struct
{
  uint64_t H[8];
  uint8_t partial[CF_SHA512_BLOCKSZ];
  uint32_t blocks;
  size_t npartial;
} cf_sha512_context;

extern void cf_sha512_init(cf_sha512_context *ctx);
extern void cf_sha512_update(cf_sha512_context *ctx, const void *data, size_t nbytes);
extern void cf_sha512_final(const cf_sha512_context *ctx, uint8_t hash[CF_SHA512_HASHSZ]);

extern const cf_chash cf_sha384;
extern const cf_chash cf_sha512;

#endif
