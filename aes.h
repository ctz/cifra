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
#ifndef AES_MAXROUNDS
# define AES_MAXROUNDS AES256_ROUNDS
#endif

/* Define this as 1 if you need side channel protection against
 * AES s-box lookups.  This has a non-trivial performance
 * penalty.
 *
 * If you are targetting a microcontroller (with no cache)
 * you can turn this off. */
#ifndef AES_SIDE_CHANNEL_PROTECTED
# define AES_SIDE_CHANNEL_PROTECTED 1
#endif

/* Define this to 1 if you don't need to decrypt anything
 * This saves space.  cf_aes_decrypt calls abort. */
#ifndef AES_ENCRYPT_ONLY
# define AES_ENCRYPT_ONLY 0
#endif

typedef struct
{
  uint32_t rounds;
  uint32_t ks[AES_BLOCKSZ / 4 * (AES_MAXROUNDS + 1)];
} cf_aes_context;

/** Fill in *ctx by expanding the given key.
 *  nkey must be 16, 24 or 32. */
extern void cf_aes_init(cf_aes_context *ctx,
                        const uint8_t *key,
                        size_t nkey);

/** Encrypts the given block, from in to out.  These may
 *  alias.
 *  Fails at runtime if ctx is invalid. */
extern void cf_aes_encrypt(const cf_aes_context *ctx,
                           const uint8_t in[AES_BLOCKSZ],
                           uint8_t out[AES_BLOCKSZ]);

/** Decrypts the given block, in place.
 *  Fails at runtime if ctx is invalid. */
extern void cf_aes_decrypt(const cf_aes_context *ctx,
                           const uint8_t in[AES_BLOCKSZ],
                           uint8_t out[AES_BLOCKSZ]);

/** Call this when you're done to erase the round keys. */
extern void cf_aes_finish(cf_aes_context *ctx);

extern const cf_prp cf_aes;

#endif
