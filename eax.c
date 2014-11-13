
#include "handy.h"
#include "prp.h"
#include "modes.h"

#include <string.h>
#include <assert.h>


static uint8_t constant_select(uint32_t cond, uint8_t nonzero, uint8_t zero)
{
  /* TODO: make this side-channel free! */
  return cond ? nonzero : zero;
}

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

  assert(prp->blocksz == 16);

  uint8_t borrow = 0;
  
  for (size_t i = prp->blocksz; i != 0; i--)
  {
    out[i - 1] = (in[i - 1] << 1) | borrow;
    borrow = (in[i - 1] >> 7);
  }

  out[15] ^= constant_select(in[0] & 0x80, 0x87, 0x00);
}

typedef struct
{
  const cf_prp *prp;
  void *prpctx;
  uint8_t B[CF_MAXBLOCK];
  uint8_t P[CF_MAXBLOCK];
} omac_ctx;

static void omac_init(omac_ctx *ctx, const cf_prp *prp, void *prpctx)
{
  uint8_t L[CF_MAXBLOCK];

  /* L = E_K(0^n) */
  memset(L, 0, prp->blocksz);
  prp->block(prpctx, cf_prp_encrypt, L, L);

  /* B = 2L */
  block_double_gf2n(prp, L, ctx->B);

  /* P = 4L */
  block_double_gf2n(prp, ctx->B, ctx->P);

  ctx->prp = prp;
  ctx->prpctx = prpctx;
}

/* Compute OMAC over firstblock (one blocks worth) and input (ninput bytes).
 * Write output to out. */
static void omac_compute(omac_ctx *ctx,
                         uint8_t firstblock[CF_MAXBLOCK],
                         const uint8_t *input, size_t ninput,
                         uint8_t out[CF_MAXBLOCK])
{
  uint8_t lastblock[CF_MAXBLOCK];

  /* CBCMAC_K(pad(M; B, P)) */

  /* nb. lastblock is our XOR offset for the last
   * CBCMAC block. */
  if (ninput % ctx->prp->blocksz == 0)
  {
    memcpy(lastblock, ctx->B, ctx->prp->blocksz);
  } else {
    size_t used = ninput % ctx->prp->blocksz;
    memcpy(lastblock, ctx->P, ctx->prp->blocksz);
    lastblock[used] ^= 0x80;
  }

  cf_cbc cbc;
  uint8_t tmp[CF_MAXBLOCK] = { 0 },
          *zero_iv = tmp;
  cf_cbc_init(&cbc, ctx->prp, zero_iv);

  cf_cbc_encrypt(&cbc, ctx->prpctx, firstblock, tmp, 1);

  size_t blocks = (ninput + ctx->prp->blocksz - 1) / ctx->prp->blocksz;
  for (size_t i = 0; i < blocks; i++)
  {
    if (i == blocks - 1)
    {
      for (size_t j = 0; j < ninput; j++)
        lastblock[j] ^= input[j];
      cf_cbc_encrypt(&cbc, ctx->prpctx, lastblock, out, 1);
    } else {
      cf_cbc_encrypt(&cbc, ctx->prpctx, input, tmp, 1);
      input += ctx->prp->blocksz;
      ninput -= ctx->prp->blocksz;
    }
  }
}

static void omac_compute_n(omac_ctx *ctx,
                           uint8_t t,
                           const uint8_t *input, size_t ninput,
                           uint8_t out[CF_MAXBLOCK])
{
  uint8_t firstblock[CF_MAXBLOCK];
  memset(firstblock, 0, ctx->prp->blocksz);
  firstblock[ctx->prp->blocksz - 1] = t;

  omac_compute(ctx, firstblock, input, ninput, out);
}

void cf_eax_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain,
                    const uint8_t *header, size_t nheader,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *cipher, /* the same size as nplain */
                    uint8_t *tag, size_t ntag)
{
  uint8_t NN[CF_MAXBLOCK],
          HH[CF_MAXBLOCK],
          CC[CF_MAXBLOCK];

  omac_ctx omac;
  omac_init(&omac, prp, prpctx);

  /* NN = OMAC_K^0(N) */
  omac_compute_n(&omac, 0, nonce, nnonce, NN);

  /* HH = OMAC_K^1(H) */
  omac_compute_n(&omac, 1, header, nheader, HH);

  /* C = CTR_K^NN(M) */
  cf_ctr ctr;
  cf_ctr_init(&ctr, prp, NN);
  cf_ctr_cipher(&ctr, prpctx, plain, cipher, nplain);

  /* CC = OMAC_K^2(C) */
  omac_compute_n(&omac, 2, cipher, nplain, CC);

  /* Tag = NN ^ CC ^ HH
   * T = Tag [ first tau bits ] */
  assert(ntag <= prp->blocksz);
  for (size_t i = 0; i < ntag; i++)
    tag[i] = NN[i] ^ CC[i] ^ HH[i];
}

int cf_eax_decrypt(const cf_prp *prp, void *prpctx,
                   const uint8_t *cipher, size_t ncipher,
                   const uint8_t *header, size_t nheader,
                   const uint8_t *nonce, size_t nnonce,
                   const uint8_t *tag, size_t ntag,
                   uint8_t *plain) /* the same size as ncipher */
{
  uint8_t NN[CF_MAXBLOCK],
          HH[CF_MAXBLOCK],
          CC[CF_MAXBLOCK];

  omac_ctx omac;
  omac_init(&omac, prp, prpctx);

  /* NN = OMAC_K^0(N) */
  omac_compute_n(&omac, 0, nonce, nnonce, NN);

  /* HH = OMAC_K^1(H) */
  omac_compute_n(&omac, 1, header, nheader, HH);

  /* CC = OMAC_K^2(C) */
  omac_compute_n(&omac, 2, cipher, ncipher, CC);

  uint8_t tt[CF_MAXBLOCK];
  assert(ntag && ntag <= prp->blocksz);
  for (size_t i = 0; i < ntag; i++)
    tt[i] = NN[i] ^ CC[i] ^ HH[i];

  if (!mem_eq(tt, tag, ntag))
    return 1;

  cf_ctr ctr;
  cf_ctr_init(&ctr, prp, NN);
  cf_ctr_cipher(&ctr, prpctx, cipher, plain, ncipher);
  return 0;
}
