#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

#define CF_SHA3_224_HASHSZ 28
#define CF_SHA3_256_HASHSZ 32
#define CF_SHA3_384_HASHSZ 48
#define CF_SHA3_512_HASHSZ 64

#define CF_SHA3_224_BLOCKSZ 144
#define CF_SHA3_256_BLOCKSZ 136
#define CF_SHA3_384_BLOCKSZ 104
#define CF_SHA3_512_BLOCKSZ 72

typedef struct
{
  /* State is a 5x5 block of 64-bit values, for Keccak-f[1600]. */
  uint64_t A[5][5];
  uint8_t partial[CF_SHA3_224_BLOCKSZ];
  size_t npartial;
  uint16_t rate, capacity; /* rate and capacity, in bytes. */
} cf_sha3_context;

extern void cf_sha3_224_init(cf_sha3_context *ctx);
extern void cf_sha3_224_update(cf_sha3_context *ctx, const void *data, size_t nbytes);
extern void cf_sha3_224_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_224_HASHSZ]);
extern void cf_sha3_224_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_224_HASHSZ]);
extern const cf_chash cf_sha3_224;

extern void cf_sha3_256_init(cf_sha3_context *ctx);
extern void cf_sha3_256_update(cf_sha3_context *ctx, const void *data, size_t nbytes);
extern void cf_sha3_256_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_256_HASHSZ]);
extern void cf_sha3_256_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_256_HASHSZ]);
extern const cf_chash cf_sha3_256;

extern void cf_sha3_384_init(cf_sha3_context *ctx);
extern void cf_sha3_384_update(cf_sha3_context *ctx, const void *data, size_t nbytes);
extern void cf_sha3_384_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_384_HASHSZ]);
extern void cf_sha3_384_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_384_HASHSZ]);
extern const cf_chash cf_sha3_384;

extern void cf_sha3_512_init(cf_sha3_context *ctx);
extern void cf_sha3_512_update(cf_sha3_context *ctx, const void *data, size_t nbytes);
extern void cf_sha3_512_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_512_HASHSZ]);
extern void cf_sha3_512_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_512_HASHSZ]);
extern const cf_chash cf_sha3_512;

#endif
