#ifndef MODES_H
#define MODES_H

#include <stddef.h>
#include <stdint.h>

#include "prp.h"

/* --- Block chaining mode --- */
typedef struct
{
  const cf_prp *prp;
  uint8_t block[CF_MAXBLOCK];
} cf_cbc;

/* Initialise CBC encryption/decryption context using selected prp and IV. */
void cf_cbc_init(cf_cbc *ctx, const cf_prp *prp, uint8_t iv[CF_MAXBLOCK]);

/* Encrypt blocks in CBC mode.  prp is the PRP's context.  input and output
 * must point to blocks * ctx->prp->blocksz bytes of storage (and may alias). */
void cf_cbc_encrypt(cf_cbc *ctx, void *prp, const uint8_t *input, uint8_t *output, size_t blocks);

/* Decrypt blocks in CBC mode.  prp is the PRP's context.  input and output
 * must point to blocks * ctx->prp->blocksz bytes of storage (and may alias). */
void cf_cbc_decrypt(cf_cbc *ctx, void *prp, const uint8_t *input, uint8_t *output, size_t blocks);

/* --- Counter mode --- */
typedef struct
{
  const cf_prp *prp;
  uint8_t block[CF_MAXBLOCK];
} cf_ctr;

/* Initialise CBC encryption/decryption context using selected prp and nonce.
 * (nb, this only increments the whole nonce as a big endian block) */
void cf_ctr_init(cf_ctr *ctx, const cf_prp *prp, uint8_t nonce[CF_MAXBLOCK]);

/* Encrypt or decrypt bytes in CTR mode.  prp is the PRP's context.
 * input and output may alias and must point to specified number of bytes. */
void cf_ctr_cipher(cf_ctr *ctx, void *prp, const uint8_t *input, uint8_t *output, size_t bytes);

/* --- EAX --- */
void cf_eax_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain,
                    const uint8_t *header, size_t nheader,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *cipher, /* the same size as nplain */
                    uint8_t *tag, size_t ntag);

/* Returns 0 on success; non-zero on error.  Nothing is written to
 * plain on error. */
int cf_eax_decrypt(const cf_prp *prp, void *prpctx,
                   const uint8_t *cipher, size_t ncipher,
                   const uint8_t *header, size_t nheader,
                   const uint8_t *nonce, size_t nnonce,
                   const uint8_t *tag, size_t ntag,
                   uint8_t *plain); /* the same size as ncipher */
#endif
