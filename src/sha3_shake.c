/*
 * cifra - embedded cryptography library
 * Written in 2020 by Silex Insight.
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "sha3_shake.h"
#include "handy.h"
#include "tassert.h"

/* function prototypes */
extern void sha3_init(cf_sha3_context *, uint16_t, uint16_t);
extern void sha3_update(cf_sha3_context *, const void *, size_t);
extern void pad_and_squeeze(cf_sha3_context *, uint8_t *, size_t);

/* SHAKE 128 */
void cf_shake_128_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 1344, 256);
  ctx->domain_pad = DOMAIN_SHAKE_PAD;
}

void cf_shake_128_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_shake_128_digest(const cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes)
{
  cf_sha3_context ours = *ctx;
  cf_shake_128_digest_final(&ours, hash, noutbytes);
}

void cf_shake_128_digest_final(cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes)
{
  pad_and_squeeze(ctx, hash, noutbytes);
}

const cf_cshake cf_shake_128 = {
  .blocksz = CF_SHAKE_128_BLOCKSZ,
  .init = (cf_cshake_init) cf_shake_128_init,
  .update = (cf_cshake_update) cf_shake_128_update,
  .digest = (cf_cshake_digest) cf_shake_128_digest
};

/* SHAKE 256 */
void cf_shake_256_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 1088, 512);
  ctx->domain_pad = DOMAIN_SHAKE_PAD;
}

void cf_shake_256_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_shake_256_digest(const cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes)
{
  cf_sha3_context ours = *ctx;
  cf_shake_256_digest_final(&ours, hash, noutbytes);
}

void cf_shake_256_digest_final(cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes)
{
  pad_and_squeeze(ctx, hash, noutbytes);
}

const cf_cshake cf_shake_256 = {
  .blocksz = CF_SHAKE_256_BLOCKSZ,
  .init = (cf_cshake_init) cf_shake_256_init,
  .update = (cf_cshake_update) cf_shake_256_update,
  .digest = (cf_cshake_digest) cf_shake_256_digest
};

/* one-shot shake function */
void cf_shake(const cf_cshake *h, const void *m, size_t nm, uint8_t *out, size_t nout)
{
  cf_sha3_context ctx;
  assert(h);
  h->init(&ctx);
  h->update(&ctx, m, nm);
  h->digest(&ctx, out, nout);
  mem_clean(&ctx, sizeof ctx);
}
