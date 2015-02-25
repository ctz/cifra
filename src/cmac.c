
#include "handy.h"
#include "prp.h"
#include "modes.h"
#include "bitops.h"
#include "blockwise.h"
#include "gf128.h"

#include <string.h>
#include <assert.h>

void cf_cmac_init(cf_cmac *ctx, const cf_prp *prp, void *prpctx)
{
  uint8_t L[CF_MAXBLOCK];
  assert(prp->blocksz == 16);

  mem_clean(ctx, sizeof *ctx);

  /* L = E_K(0^n) */
  mem_clean(L, prp->blocksz);
  prp->encrypt(prpctx, L, L);

  /* B = 2L */
  cf_gf128 gf;
  cf_gf128_frombytes_be(L, gf);
  cf_gf128_double(gf, gf);
  cf_gf128_tobytes_be(gf, ctx->B);

  /* P = 4L */
  cf_gf128_double(gf, gf);
  cf_gf128_tobytes_be(gf, ctx->P);

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

