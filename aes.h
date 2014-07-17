#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCKSZ 16

/* This works for small implementations which only support
 * 128-bit key AES.  Default is good for 128- to 256-bit keys. */
#ifndef AES_MAXROUNDS
# define AES_MAXROUNDS 14
#endif

typedef struct
{
  uint32_t rounds;
  uint32_t ks[AES_BLOCKSZ / 4 * (AES_MAXROUNDS + 1)];
} aes_context;


/** Fill in *ctx by expanding the given key.
 *  nkey must be 16, 24 or 32. */
extern void aes_init(aes_context *ctx,
                     const uint8_t *key,
                     size_t nkey);

/** Encrypts the given block, from in to out.  These may
 *  alias.
 *  Fails at runtime if ctx is invalid. */
extern void aes_encrypt(const aes_context *ctx,
                        const uint8_t in[AES_BLOCKSZ],
                        uint8_t out[AES_BLOCKSZ]);

/** Decrypts the given block, in place.
 *  Fails at runtime if ctx is invalid. */
extern void aes_decrypt(const aes_context *ctx,
                        const uint8_t in[AES_BLOCKSZ],
                        uint8_t out[AES_BLOCKSZ]);

/** Call this when you're done to erase the round keys. */
extern void aes_finish(aes_context *ctx);

#endif
