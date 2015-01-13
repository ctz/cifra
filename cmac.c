
#include "handy.h"
#include "prp.h"
#include "modes.h"
#include "bitops.h"
#include "blockwise.h"

#include <string.h>
#include <assert.h>

static void block_double_gf2n(const cf_prp *prp,
                              const uint8_t in[CF_MAXBLOCK],
                              uint8_t out[CF_MAXBLOCK])
{
  /*
   * For n = 128 the indicated polynomial is x^128 + x^7 + x^2 + x + 1.
   *
   * In that case,
   *
   *   2L = L<<1
   *
   * if the first bit of L is 0 and
   *
   *   2L = (L<<1) ^ 0^120 10000111
   *  
   * otherwise, where L<<1 means the left shift of L by one position
   * (the first bit vanishing and a zero entering into the last bit).
   */
  uint8_t table[2] = { 0x00, 0x87 };

  assert(prp->blocksz == 16);

  uint8_t borrow = 0;
  
  for (size_t i = prp->blocksz; i != 0; i--)
  {
    out[i - 1] = (in[i - 1] << 1) | borrow;
    borrow = (in[i - 1] >> 7);
  }

  out[15] ^= select_u8(!!(in[0] & 0x80), table, 2);
}

void cf_cmac_init(cf_cmac *ctx, const cf_prp *prp, void *prpctx)
{
  uint8_t L[CF_MAXBLOCK];

  mem_clean(ctx, sizeof *ctx);

  /* L = E_K(0^n) */
  mem_clean(L, prp->blocksz);
  prp->block(prpctx, cf_prp_encrypt, L, L);

  /* B = 2L */
  block_double_gf2n(prp, L, ctx->B);

  /* P = 4L */
  block_double_gf2n(prp, ctx->B, ctx->P);

  ctx->prp = prp;
  ctx->prpctx = prpctx;
}

void cf_cmac_sign(cf_cmac *ctx, const uint8_t *data, size_t len, uint8_t out[CF_MAXBLOCK])
{
  cf_cmac_stream stream;
  stream.cmac = *ctx;
  cf_cmac_stream_reset(&stream);
  cf_cmac_stream_update(&stream, data, len, 1);
  cf_cmac_stream_final(&stream, out);
}

void cf_cmac_stream_init(cf_cmac_stream *ctx, const cf_prp *prp, void *prpctx)
{
  cf_cmac_init(&ctx->cmac, prp, prpctx);
  cf_cmac_stream_reset(ctx);
}

void cf_cmac_stream_reset(cf_cmac_stream *ctx)
{
  uint8_t iv_zero[CF_MAXBLOCK] = { 0 };
  cf_cbc_init(&ctx->cbc, ctx->cmac.prp, ctx->cmac.prpctx, iv_zero);
  mem_clean(ctx->buffer, sizeof ctx->buffer);
  ctx->used = 0;
  ctx->processed = 0;
  ctx->finalised = 0;
}

static void cmac_process(void *vctx, const uint8_t *block)
{
  cf_cmac_stream *ctx = vctx;
  uint8_t output[CF_MAXBLOCK];
  cf_cbc_encrypt(&ctx->cbc, block, output, 1);
  ctx->processed += ctx->cmac.prp->blocksz;
}

static void cmac_process_final(cf_cmac_stream *ctx, const uint8_t *block,
                               const uint8_t *xor)
{
  uint8_t input[CF_MAXBLOCK];
  uint8_t output[CF_MAXBLOCK];
  xor_bb(input, block, xor, ctx->cmac.prp->blocksz);
  cf_cbc_encrypt(&ctx->cbc, input, output, 1);
  ctx->processed += ctx->cmac.prp->blocksz;
  /* signature is in ctx->cbc.block. */
}

static void cmac_process_final_nopad(void *vctx, const uint8_t *block)
{
  cf_cmac_stream *ctx = vctx;
  cmac_process_final(ctx, block, ctx->cmac.B);
}

static void cmac_process_final_pad(void *vctx, const uint8_t *block)
{
  cf_cmac_stream *ctx = vctx;
  cmac_process_final(ctx, block, ctx->cmac.P);
}

void cf_cmac_stream_update(cf_cmac_stream *ctx, const uint8_t *data, size_t len, int isfinal)
{
  size_t blocksz = ctx->cmac.prp->blocksz;
  cf_blockwise_in_fn final_fn = cmac_process;
  int needpad = 0;

  if (isfinal)
  {
    assert(!ctx->finalised);
    ctx->finalised = 1;

    /* If we have a whole number of blocks, and at least 1 block, we XOR in B.
     * Otherwise, we need to pad and XOR in P. */
    if (((len + ctx->used) & 0xf) == 0 &&
        !(len == 0 && ctx->used == 0 && ctx->processed == 0))
      final_fn = cmac_process_final_nopad;
    else
      needpad = 1;
  }

  /* Input data */
  cf_blockwise_accumulate_final(ctx->buffer, &ctx->used, blocksz,
                                data, len,
                                cmac_process,
                                final_fn, ctx);

  /* Input padding */
  if (needpad)
  {
    uint8_t pad_block[CF_MAXBLOCK] = { 0x80 };
    cf_blockwise_accumulate(ctx->buffer, &ctx->used, blocksz,
                            pad_block, blocksz - ctx->used,
                            cmac_process_final_pad, ctx);
  }
}

void cf_cmac_stream_final(cf_cmac_stream *ctx, uint8_t out[CF_MAXBLOCK])
{
  assert(ctx->finalised);
  memcpy(out, ctx->cbc.block, ctx->cmac.prp->blocksz);
}

