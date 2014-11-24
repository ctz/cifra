#ifndef CHASH_H
#define CHASH_H

#include <stddef.h>
#include <stdint.h>

typedef void (*cf_chash_init)(void *ctx);
typedef void (*cf_chash_update)(void *ctx, const void *data, size_t bytes);
typedef void (*cf_chash_final)(const void *ctx, uint8_t *hash);

/* Describes an incremental hash function in a general way. */
typedef struct
{
  size_t hashsz;
  size_t blocksz;
  size_t ctxsz;
  cf_chash_init init;
  cf_chash_update update;
  cf_chash_final final;
} cf_chash;

#define CF_CHASH_MAXCTX 224
#define CF_CHASH_MAXBLK 128
#define CF_MAXHASH 64

/* A type usable with any chash as a context. */
typedef union
{
  uint8_t ctx[CF_CHASH_MAXCTX];
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
} cf_chash_ctx;

/* One shot hashing: out = h(m). */
void cf_hash(const cf_chash *h, const void *m, size_t nm, uint8_t *out);

#endif
