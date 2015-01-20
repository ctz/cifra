
#include "handy.h"
#include "prp.h"
#include "modes.h"
#include "blockwise.h"
#include "bitops.h"
#include "gf128.h"

#include <string.h>
#include <assert.h>

/* Incremental GHASH computation. */
typedef struct
{
  uint8_t H[16];
  uint8_t Y[16];
  uint8_t buffer[16];
  size_t buffer_used;
  uint64_t len_aad;
  uint64_t len_cipher;
  unsigned state;
#define STATE_INVALID 0
#define STATE_AAD 1
#define STATE_CIPHER 2
} ghash_ctx;

static void ghash_init(ghash_ctx *ctx, uint8_t H[16])
{
  memset(ctx, 0, sizeof *ctx);
  memcpy(ctx->H, H, 16);
  ctx->state = STATE_AAD;
}

static void ghash_block(void *vctx, const uint8_t *data)
{
  ghash_ctx *ctx = vctx;
  cf_gf128_add(data, ctx->Y, ctx->Y);
  cf_gf128_mul(ctx->Y, ctx->H, ctx->Y);
}

static void ghash_add(ghash_ctx *ctx, const uint8_t *buf, size_t n)
{
  cf_blockwise_accumulate(ctx->buffer, &ctx->buffer_used,
                          16,
                          buf, n,
                          ghash_block,
                          ctx);
}

static void ghash_add_pad(ghash_ctx *ctx)
{
  uint8_t byte = 0x00;
  while (ctx->buffer_used != 0)
    ghash_add(ctx, &byte, 1);
}

static void ghash_add_aad(ghash_ctx *ctx, const uint8_t *buf, size_t n)
{
  assert(ctx->state == STATE_AAD);
  ctx->len_aad += n;
  ghash_add(ctx, buf, n);
}

static void ghash_add_cipher(ghash_ctx *ctx, const uint8_t *buf, size_t n)
{
  if (ctx->state == STATE_AAD)
  {
    ghash_add_pad(ctx);
    ctx->state = STATE_CIPHER;
  }
  
  assert(ctx->state == STATE_CIPHER);
  ctx->len_cipher += n;
  ghash_add(ctx, buf, n);
}

static void ghash_final(ghash_ctx *ctx, uint8_t out[16])
{
  uint8_t lenbuf[8];

  if (ctx->state == STATE_AAD || ctx->state == STATE_CIPHER)
  {
    ghash_add_pad(ctx);
    ctx->state = STATE_INVALID;
  }

  /* Add len(A) || len(C) */
  write64_be(ctx->len_aad * 8, lenbuf);
  ghash_add(ctx, lenbuf, sizeof lenbuf);

  write64_be(ctx->len_cipher * 8, lenbuf);
  ghash_add(ctx, lenbuf, sizeof lenbuf);

  assert(ctx->buffer_used == 0);
  memcpy(out, ctx->Y, 16);
}

void cf_gcm_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain,
                    const uint8_t *header, size_t nheader,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *cipher, /* the same size as nplain */
                    uint8_t *tag, size_t ntag)
{
  uint8_t H[16] = { 0 };
  uint8_t Y0[16]; 

  /* H = E_K(0^128) */
  prp->block(prpctx, cf_prp_encrypt, H, H);

  /* Produce CTR nonce, Y_0:
   *
   * if len(IV) == 96
   *   Y_0 = IV || 0^31 || 1
   * otherwise
   *   Y_0 = GHASH(H, {}, IV)
   */

  if (nnonce == 12)
  {
    memcpy(Y0, nonce, nnonce);
    Y0[12] = Y0[13] = Y0[14] = 0x00;
    Y0[15] = 0x01;
  } else {
    ghash_ctx gh;
    ghash_init(&gh, H);
    ghash_add_cipher(&gh, nonce, nnonce);
    ghash_final(&gh, Y0);
  }

  /* Hash AAD */
  ghash_ctx gh;
  ghash_init(&gh, H);
  ghash_add_aad(&gh, header, nheader);

  /* Produce ciphertext */
  uint8_t e_Y0[16] = { 0 };
  cf_ctr ctr;
  cf_ctr_init(&ctr, prp, prpctx, Y0);
  cf_ctr_custom_counter(&ctr, 12, 4); /* counter is 2^32 */
  cf_ctr_cipher(&ctr, e_Y0, e_Y0, sizeof e_Y0); /* first block is tag offset */
  cf_ctr_cipher(&ctr, plain, cipher, nplain);

  /* Hash ciphertext */
  ghash_add_cipher(&gh, cipher, nplain);

  /* Post-process ghash output */
  uint8_t full_tag[16] = { 0 };
  ghash_final(&gh, full_tag);
  
  assert(ntag > 1 && ntag <= 16);
  xor_bb(tag, full_tag, e_Y0, ntag);
}
