
#include "prp.h"
#include "modes.h"

#include <string.h>

static void xorbb(uint8_t *out, const uint8_t *x, const uint8_t *y, size_t bytes)
{
  while (bytes--)
    *out++ = *x++ ^ *y++;
}

/* CBC */
void cf_cbc_init(cf_cbc *ctx, const cf_prp *prp, uint8_t iv[CF_MAXBLOCK])
{
  ctx->prp = prp;
  memcpy(ctx->block, iv, prp->blocksz);
}

void cf_cbc_encrypt(cf_cbc *ctx, void *prp, const uint8_t *input, uint8_t *output, size_t blocks)
{
  uint8_t buf[CF_MAXBLOCK];
  size_t nblk = ctx->prp->blocksz;

  while (blocks--)
  {
    xorbb(buf, input, ctx->block, nblk);
    ctx->prp->block(prp, cf_prp_encrypt, buf, ctx->block);
    memcpy(output, ctx->block, nblk);
    input += nblk;
    output += nblk;
  }
}

void cf_cbc_decrypt(cf_cbc *ctx, void *prp, const uint8_t *input, uint8_t *output, size_t blocks)
{
  uint8_t buf[CF_MAXBLOCK];
  size_t nblk = ctx->prp->blocksz;

  while (blocks--)
  {
    ctx->prp->block(prp, cf_prp_decrypt, input, buf);
    xorbb(output, buf, ctx->block, nblk);
    memcpy(ctx->block, input, nblk);
    input += nblk;
    output += nblk;
  }
}

/* CTR */
void cf_ctr_init(cf_ctr *ctx, const cf_prp *prp, uint8_t nonce[CF_MAXBLOCK])
{
  ctx->prp = prp;
  memcpy(ctx->block, nonce, prp->blocksz);
}

static void next_block(uint8_t *block, size_t nb)
{
  nb--;
  while (1)
  {
    if (++block[nb] != 0)
      return;
    if (nb == 0)
      return;
    nb--;
  }
}

void cf_ctr_cipher(cf_ctr *ctx, void *prp, const uint8_t *input, uint8_t *output, size_t bytes)
{
  uint8_t buf[CF_MAXBLOCK];
  size_t nblk = ctx->prp->blocksz;

  while (bytes)
  {
    size_t taken = bytes > nblk ? nblk : bytes;
    ctx->prp->block(prp, cf_prp_encrypt, ctx->block, buf);
    xorbb(output, input, buf, taken);
    output += taken;
    input += taken;
    bytes -= taken;
    next_block(ctx->block, nblk);
  }
}
