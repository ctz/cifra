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

/* Discards the rest of this block of key stream. */
void cf_ctr_discard_block(cf_ctr *ctx);

/* --- CBCMAC --- */

/* Stream interface to CBCMAC signing.  You shouldn't use CBCMAC.
 * Use CMAC instead. */
typedef struct
{
  const cf_prp *prp;
  void *prpctx;
  cf_cbc cbc;
  uint8_t buffer[CF_MAXBLOCK];
  size_t used;
} cf_cbcmac_stream;

/* Initialise CBCMAC signing context using selected prp. */
void cf_cbcmac_stream_init(cf_cbcmac_stream *ctx, const cf_prp *prp, void *prpctx);

/* Reset the streaming signing context, to sign a new message. */
void cf_cbcmac_stream_reset(cf_cbcmac_stream *ctx);

/* Process ndata bytes at data. */
void cf_cbcmac_stream_update(cf_cbcmac_stream *ctx, const uint8_t *data, size_t ndata);

/* Output the MAC to ctx->prp->blocksz bytes at out.
 * ctx->used must be zero: the inputed message must be an exact number of
 * blocks. */
void cf_cbcmac_stream_nopad_final(cf_cbcmac_stream *ctx, uint8_t out[CF_MAXBLOCK]);

/* Output the MAC to ctx->prp->blocksz bytes at out.
 *
 * The message is padded with PKCS#5 padding. */
void cf_cbcmac_stream_pad_final(cf_cbcmac_stream *ctx, uint8_t out[CF_MAXBLOCK]);

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

/** EAX authenticated encryption mode.
 *
 *  - prp and prpctx describe the block cipher to use.
 *  - nplain bytes at plain is the message plaintext.
 *    nplain may be zero.
 *  - nheader bytes at header is the additionally
 *    authenticated data.  nheader may be zero.
 *  - nnonce bytes at nonce is the nonce (of any
 *    length).  This must not repeat for any given key.
 *  - nplain bytes of ciphertext is written at cipher.
 *    This must point to at least that much storage.
 *  - ntag bytes of authentication tag is written to tag.
 *    ntag must be non-zero and no greater than prp->blocksz.
 *
 *  This function does not fail.
 */
void cf_eax_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain,
                    const uint8_t *header, size_t nheader,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *cipher, /* the same size as nplain */
                    uint8_t *tag, size_t ntag);

/** EAX authenticated decryption mode.
 *
 *  - prp and prpctx describe the block cipher to use.
 *  - ncipher bytes at cipher is the message ciphertext.
 *    ncipher may be zero.
 *  - nheader bytes at header is the additionally
 *    authenticated data.  nheader may be zero.
 *  - nnonce bytes at nonce is the nonce (of any
 *    length).
 *  - ntag bytes of authentication tag is read from tag.
 *    ntag must be non-zero and no greater than prp->blocksz.
 *  - ncipher bytes of plaintext is written at plain.
 *    This must point to at least that much storage.
 *
 * Returns 0 on success; non-zero on error.  Nothing is written to
 * plain on error.
 */
int cf_eax_decrypt(const cf_prp *prp, void *prpctx,
                   const uint8_t *cipher, size_t ncipher,
                   const uint8_t *header, size_t nheader,
                   const uint8_t *nonce, size_t nnonce,
                   const uint8_t *tag, size_t ntag,
                   uint8_t *plain); /* the same size as ncipher */

/* --- GCM --- */
/** GCM authenticated encryption mode.
 *
 *  - prp and prpctx describe the block cipher to use.
 *  - nplain bytes at plain is the message plaintext.
 *    nplain may be zero.
 *  - nheader bytes at header is the additionally
 *    authenticated data.  nheader may be zero.
 *  - nnonce bytes at nonce is the nonce (of any length,
 *    with 12 byte values being strongly recommended.)
 *    This must not repeat for any given key.
 *  - nplain bytes of ciphertext is written at cipher.
 *    This must point to at least that much storage.
 *  - ntag bytes of authentication tag is written to tag.
 *    ntag must be non-zero and no greater than prp->blocksz.
 *
 *  This function does not fail.
 */
void cf_gcm_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain,
                    const uint8_t *header, size_t nheader,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *cipher, /* the same size as nplain */
                    uint8_t *tag, size_t ntag);

/** GCM authenticated decryption mode.
 *
 *  - prp and prpctx describe the block cipher to use.
 *  - ncipher bytes at cipher is the message ciphertext.
 *    ncipher may be zero.
 *  - nheader bytes at header is the additionally
 *    authenticated data.  nheader may be zero.
 *  - nnonce bytes at nonce is the nonce (of any
 *    length).
 *  - ntag bytes of authentication tag is read from tag.
 *    ntag must be non-zero and no greater than prp->blocksz.
 *  - ncipher bytes of plaintext is written at plain.
 *    This must point to at least that much storage.
 *
 * Returns 0 on success; non-zero on error.  Nothing is written to
 * plain on error.
 */
int cf_gcm_decrypt(const cf_prp *prp, void *prpctx,
                   const uint8_t *cipher, size_t ncipher,
                   const uint8_t *header, size_t nheader,
                   const uint8_t *nonce, size_t nnonce,
                   const uint8_t *tag, size_t ntag,
                   uint8_t *plain); /* the same size as ncipher */

/* --- CCM --- */
/** CCM authenticated encryption mode.
 *
 *  - prp and prpctx describe the block cipher to use.
 *  - nplain bytes at plain is the message plaintext.
 *    nplain may be zero.  nplain must meet the constraints
 *    imposed on it by L.
 *  - L is the length of the message length encoding.  This must
 *    be in the interval [2, 8] and gives a maximum message
 *    size of 2 ** 8L bytes.
 *  - nheader bytes at header is the additionally
 *    authenticated data.  nheader may be zero.
 *  - nnonce bytes at nonce is the nonce (of exactly 15 - L
 *    octets for a 128-bit block cipher).
 *    This must not repeat for any given key.
 *  - ntag bytes of authentication tag is written to tag.
 *    ntag must be 4, 6, 8, 10, 12, 14 or 16.
 *  - nplain bytes of ciphertext is written at cipher.
 *    This must point to at least that much storage.
 */
void cf_ccm_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain, size_t L,
                    const uint8_t *header, size_t nheader,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *tag, size_t ntag,
                    uint8_t *cipher);

/** CCM authenticated decryption mode.
 *
 *  - prp and prpctx describe the block cipher to use.
 *  - ncipher bytes at cipher is the message ciphertext.
 *  - L is the length of the message length encoding.  This must
 *    be in the interval [2, 8] and gives a maximum message
 *    size of 2 ** 8L bytes.
 *  - nheader bytes at header is the additionally
 *    authenticated data.  nheader may be zero.
 *  - nnonce bytes at nonce is the nonce (of exactly 15 - L
 *    octets for a 128-bit block cipher).
 *    This must not repeat for any given key.
 *  - ntag bytes of authentication tag is expected at tag.
 *    ntag must be 4, 6, 8, 10, 12, 14 or 16.
 *  - ncipher bytes of plaintext is written at plain.
 *    This must point to at least that much storage.
 *
 * Returns 0 on success; non-zero on error.  Plain is cleared
 * on error.
 */
int cf_ccm_decrypt(const cf_prp *prp, void *prpctx,
                   const uint8_t *cipher, size_t ncipher, size_t L,
                   const uint8_t *header, size_t nheader,
                   const uint8_t *nonce, size_t nnonce,
                   const uint8_t *tag, size_t ntag,
                   uint8_t *plain);
#endif
