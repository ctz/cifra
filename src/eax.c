
#include "handy.h"
#include "prp.h"
#include "modes.h"

#include <string.h>
#include <assert.h>

static void cmac_compute_n(cf_cmac_stream *ctx,
                           uint8_t t,
                           const uint8_t *input, size_t ninput,
                           uint8_t out[CF_MAXBLOCK])
{
  size_t blocksz = ctx->cmac.prp->blocksz;
  uint8_t firstblock[CF_MAXBLOCK];
  memset(firstblock, 0, blocksz);
  firstblock[blocksz - 1] = t;

  cf_cmac_stream_reset(ctx);
  cf_cmac_stream_update(ctx, firstblock, blocksz, 0);
  cf_cmac_stream_update(ctx, input, ninput, 1);
  cf_cmac_stream_final(ctx, out);
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

  cf_cmac_stream cmac;
  cf_cmac_stream_init(&cmac, prp, prpctx);

  /* NN = OMAC_K^0(N) */
  cmac_compute_n(&cmac, 0, nonce, nnonce, NN);

  /* HH = OMAC_K^1(H) */
  cmac_compute_n(&cmac, 1, header, nheader, HH);

  /* C = CTR_K^NN(M) */
  cf_ctr ctr;
  cf_ctr_init(&ctr, prp, prpctx, NN);
  cf_ctr_cipher(&ctr, plain, cipher, nplain);

  /* CC = OMAC_K^2(C) */
  cmac_compute_n(&cmac, 2, cipher, nplain, CC);

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

  cf_cmac_stream cmac;
  cf_cmac_stream_init(&cmac, prp, prpctx);

  /* NN = OMAC_K^0(N) */
  cmac_compute_n(&cmac, 0, nonce, nnonce, NN);

  /* HH = OMAC_K^1(H) */
  cmac_compute_n(&cmac, 1, header, nheader, HH);

  /* CC = OMAC_K^2(C) */
  cmac_compute_n(&cmac, 2, cipher, ncipher, CC);

  uint8_t tt[CF_MAXBLOCK];
  assert(ntag && ntag <= prp->blocksz);
  for (size_t i = 0; i < ntag; i++)
    tt[i] = NN[i] ^ CC[i] ^ HH[i];

  if (!mem_eq(tt, tag, ntag))
    return 1;

  cf_ctr ctr;
  cf_ctr_init(&ctr, prp, prpctx, NN);
  cf_ctr_cipher(&ctr, cipher, plain, ncipher);
  return 0;
}