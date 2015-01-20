#ifndef MODES_H
#define MODES_H

#include <stddef.h>
#include <stdint.h>

#include "prp.h"

/* --- Block chaining mode --- */
typedef struct
{
  const cf_prp *prp;
  void *prpctx;
  uint8_t block[CF_MAXBLOCK];
} cf_cbc;

/* Initialise CBC encryption/decryption context using selected prp, prp context and IV. */
void cf_cbc_init(cf_cbc *ctx, const cf_prp *prp, void *prpctx, uint8_t iv[CF_MAXBLOCK]);

/* Encrypt blocks in CBC mode.  input and output
 * must point to blocks * ctx->prp->blocksz bytes of storage (and may alias). */
void cf_cbc_encrypt(cf_cbc *ctx, const uint8_t *input, uint8_t *output, size_t blocks);

/* Decrypt blocks in CBC mode.  input and output
 * must point to blocks * ctx->prp->blocksz bytes of storage (and may alias). */
void cf_cbc_decrypt(cf_cbc *ctx, const uint8_t *input, uint8_t *output, size_t blocks);

/* --- Counter mode --- */
typedef struct
{
  const cf_prp *prp;
  void *prpctx;
  uint8_t nonce[CF_MAXBLOCK];
  uint8_t keymat[CF_MAXBLOCK];
  size_t nkeymat;
  size_t counter_offset;
  size_t counter_width;
} cf_ctr;

/* Initialise CTR encryption/decryption context using selected prp and nonce.
 * (nb, this only increments the whole nonce as a big endian block) */
void cf_ctr_init(cf_ctr *ctx, const cf_prp *prp, void *prpctx, uint8_t nonce[CF_MAXBLOCK]);

/* Set the location and width of the nonce counter.  
 *
 * eg. offset = 12, width = 4 means the counter is mod 2^32 and placed
 * at the end of the nonce. */
void cf_ctr_custom_counter(cf_ctr *ctx, size_t offset, size_t width);

/* Encrypt or decrypt bytes in CTR mode.
 * input and output may alias and must point to specified number of bytes. */
void cf_ctr_cipher(cf_ctr *ctx, const uint8_t *input, uint8_t *output, size_t bytes);

/* --- CMAC --- */
typedef struct
{
  const cf_prp *prp;
  void *prpctx;
  uint8_t B[CF_MAXBLOCK];
  uint8_t P[CF_MAXBLOCK];
} cf_cmac;

/* Initialise CMAC signing context using selected prp. */
void cf_cmac_init(cf_cmac *ctx, const cf_prp *prp, void *prpctx);

/* CMAC sign the given data.  The MAC is written to ctx->prp->blocksz
 * bytes at out.   This is a one-shot function. */
void cf_cmac_sign(cf_cmac *ctx, const uint8_t *data, size_t bytes,
                  uint8_t out[CF_MAXBLOCK]);

/* Stream interface to CMAC signing. */
typedef struct
{
  cf_cmac cmac;
  cf_cbc cbc;
  uint8_t buffer[CF_MAXBLOCK];
  size_t used;
  size_t processed;
  int finalised;
} cf_cmac_stream;

/* Initialise CMAC streaming signing context using selected prp. */
void cf_cmac_stream_init(cf_cmac_stream *ctx, const cf_prp *prp, void *prpctx);

/* Reset the streaming signing context, to sign a new message. */
void cf_cmac_stream_reset(cf_cmac_stream *ctx);

/* Process ndata bytes at data.  isfinal is non-zero if this is the last piece
 * of data. */
void cf_cmac_stream_update(cf_cmac_stream *ctx, const uint8_t *data, size_t ndata,
                           int isfinal);

/* Output the MAC to ctx->cmac->prp->blocksz bytes at out.
 * cf_cmac_stream_update with isfinal non-zero must have been called
 * since the last _init/_reset. */
void cf_cmac_stream_final(cf_cmac_stream *ctx, uint8_t out[CF_MAXBLOCK]);

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

/* --- GCM --- */
void cf_gcm_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain,
                    const uint8_t *header, size_t nhead,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *cipher, /* the same size as nplain */
                    uint8_t *tag, size_t ntag);

/* Returns 0 on success; non-zero on error.  Nothing is written to
 * plain on error. */
int cf_gcm_decrypt(const cf_prp *prp, void *prpctx,
                   const uint8_t *cipher, size_t ncipher,
                   const uint8_t *header, size_t nheader,
                   const uint8_t *nonce, size_t nnonce,
                   const uint8_t *tag, size_t ntag,
                   uint8_t *plain); /* the same size as ncipher */
#endif
