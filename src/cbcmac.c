
#include "handy.h"
#include "prp.h"
#include "modes.h"
#include "bitops.h"
#include "blockwise.h"
#include "gf128.h"

#include <string.h>
#include <assert.h>

void cf_cbcmac_stream_init(cf_cbcmac_stream *ctx, const cf_prp *prp, void *prpctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->prp = prp;
  ctx->prpctx = prpctx;
  cf_cbcmac_stream_reset(ctx);
}

void cf_cbcmac_stream_reset(cf_cbcmac_stream *ctx)
{
  uint8_t iv_zero[CF_MAXBLOCK] = { 0 };
  cf_cbc_init(&ctx->cbc, ctx->prp, ctx->prpctx, iv_zero);
  mem_clean(ctx->buffer, sizeof ctx->buffer);
  ctx->used = 0;
}

static void cbcmac_process(void *vctx, const uint8_t *block)
{
  cf_cbcmac_stream *ctx = vctx;
  uint8_t output[CF_MAXBLOCK];
  cf_cbc_encrypt(&ctx->cbc, block, output, 1);
}

void cf_cbcmac_stream_update(cf_cbcmac_stream *ctx, const uint8_t *data, size_t len)
{
  cf_blockwise_accumulate(ctx->buffer, &ctx->used, ctx->prp->blocksz,
                          data, len,
                          cbcmac_process,
                          ctx);
}

void cf_cbcmac_stream_nopad_final(cf_cbcmac_stream *ctx, uint8_t out[CF_MAXBLOCK])
{
  assert(ctx->used == 0);
  memcpy(out, ctx->cbc.block, ctx->prp->blocksz);
}

void cf_cbcmac_stream_pad_final(cf_cbcmac_stream *ctx, uint8_t out[CF_MAXBLOCK])
{
  uint8_t npad = ctx->prp->blocksz - ctx->used;
  for (size_t i = 0; i < npad; i++)
    cf_cbcmac_stream_update(ctx, &npad, 1);
  cf_cbcmac_stream_nopad_final(ctx, out);
}
