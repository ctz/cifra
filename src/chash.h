/**
 * @brief Cryptographic hash function abstraction.
 */

#ifndef CHASH_H
#define CHASH_H

#include <stddef.h>
#include <stdint.h>

/** Initialises the context in preparation for hashing a message with
 *  _update. */
typedef void (*cf_chash_init)(void *ctx);

/** Hashes @p bytes data at @p data, updating the contents of @p ctx. */
typedef void (*cf_chash_update)(void *ctx, const void *data, size_t bytes);

/** Completes the operation, writing @p cf_chash.hashsz bytes to @p hash.
 *
 *  This function does not change @p ctx -- any padding which needs doing
 *  must be done seperately (in a copy of @p ctx, say).
 *
 *  This means you can interlave @p _update and @p _digest calls to
 *  learn @p H(a) and @p H(a||b) without hashing @p a twice. */
typedef void (*cf_chash_digest)(const void *ctx, uint8_t *hash);

/** @p cf_chash describes an incremental hash function in an abstract way. */
typedef struct
{
  /** Output length (bytes). */
  size_t hashsz;

  /** Internal block size (bytes). */
  size_t blocksz;

  /** Size of the context structure (bytes).  This must
   *  be <= @ref CF_CHASH_MAXCTX. */
  size_t ctxsz;

  /** Context initialisation function. */
  cf_chash_init init;

  /** Incremental hash function. */
  cf_chash_update update;

  /** Hash completion operation. */
  cf_chash_digest digest;
} cf_chash;

/** The maximum size of a @ref cf_chash_ctx.  This allows
 *  use to put a structure in automatic storage that can
 *  store working data for any supported hash function. */
#define CF_CHASH_MAXCTX 360

/** Maximum hash function block size (bytes). */
#define CF_CHASH_MAXBLK 128

/** Maximum hash function output (bytes). */
#define CF_MAXHASH 64

/** A type usable with any chash as a context. */
typedef union
{
  uint8_t ctx[CF_CHASH_MAXCTX];
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
} cf_chash_ctx;

/** One shot hashing: out = h(m).
 *
 *  Using @p h, @p nm bytes at @p m are hashed and @p h->hashsz bytes
 *  of result is written to the buffer @p out. */
void cf_hash(const cf_chash *h, const void *m, size_t nm, uint8_t *out);

#endif
