/**
 * @brief The AES/Rijndael128 block cipher.
 */

#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#include "prp.h"

#define AES_BLOCKSZ 16

/* --- Size/speed/security configuration --- */

/* Round counts for different key sizes. */
#define AES128_ROUNDS 10
#define AES192_ROUNDS 12
#define AES256_ROUNDS 14

/* You can reduce the maximum number of rounds this implementation
 * supports. This reduces the storage needed by cf_aes_context.
 *
 * Default is good for 128- to 256-bit keys. */
#ifndef CF_AES_MAXROUNDS
# define CF_AES_MAXROUNDS AES256_ROUNDS
#endif

/* Define this to 1 if you don't need to decrypt anything
 * This saves space.  cf_aes_decrypt calls abort. */
#ifndef CF_AES_ENCRYPT_ONLY
# define CF_AES_ENCRYPT_ONLY 0
#endif

typedef struct
{
  /** Number of rounds. */
  uint32_t rounds;

  /** Scheduled key material. */
  uint32_t ks[AES_BLOCKSZ / 4 * (CF_AES_MAXROUNDS + 1)];
} cf_aes_context;

/** AES key scheduling.
 *
 *  Fill in @p *ctx by expanding the given key.
 *  @p nkey must be 16, 24 or 32. */
extern void cf_aes_init(cf_aes_context *ctx,
                        const uint8_t *key,
                        size_t nkey);

/** Encrypts the given block, from @p in to @p out.  These
 *  may alias.
 *
 *  Fails at runtime if @p ctx is invalid. */
extern void cf_aes_encrypt(const cf_aes_context *ctx,
                           const uint8_t in[AES_BLOCKSZ],
                           uint8_t out[AES_BLOCKSZ]);

/** Decrypts the given block, from @p in to @p out.  These
 *  may alias.
 *
 *  Fails at runtime if @p ctx is invalid. */
extern void cf_aes_decrypt(const cf_aes_context *ctx,
                           const uint8_t in[AES_BLOCKSZ],
                           uint8_t out[AES_BLOCKSZ]);

/** Erase scheduled key material.
 *
 *  Call this when you're done to erase the round keys. */
extern void cf_aes_finish(cf_aes_context *ctx);

/** Abstract interface to AES. */
extern const cf_prp cf_aes;

#endif
