#ifndef SHA2_H
#define SHA2_H

#include <stddef.h>
#include <stdint.h>

#define SHA224_HASHSZ 28
#define SHA224_BLOCKSZ 64

#define SHA256_HASHSZ 32
#define SHA256_BLOCKSZ 64

typedef struct
{
  uint32_t H[8];                    /* State. */
  uint8_t partial[SHA256_BLOCKSZ];  /* Partial block of input. */
  uint32_t blocks;                  /* Number of full blocks processed into H. */
  uint8_t npartial;                 /* Number of bytes in prefix of partial. */
} sha256_context;

extern void sha256_init(sha256_context *ctx);
extern void sha256_update(sha256_context *ctx, const void *data, size_t nbytes);
extern void sha256_digest(const sha256_context *ctx, uint8_t hash[SHA256_HASHSZ]);
extern void sha256_clean(sha256_context *ctx);

/* nb. SHA224 uses SHA256's underlying types. */
extern void sha224_init(sha256_context *ctx);
extern void sha224_update(sha256_context *ctx, const void *data, size_t nbytes);
extern void sha224_digest(const sha256_context *ctx, uint8_t hash[SHA224_HASHSZ]);
extern void sha224_clean(sha256_context *ctx);

#endif
