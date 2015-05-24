/*
 * cifra - embedded cryptography library
 * Written in 2014 by Joseph Birr-Pixton <jpixton@gmail.com>
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


#include "norx.h"
#include "bitops.h"
#include "handy.h"
#include "blockwise.h"
#include "tassert.h"

#include <string.h>

typedef struct
{
  uint32_t s[16];
} cf_norx32_ctx;

/* Domain separation constants */
#define DOMAIN_HEADER   0x01
#define DOMAIN_PAYLOAD  0x02
#define DOMAIN_TRAILER  0x04
#define DOMAIN_TAG      0x08

#define WORD_BYTES 4
#define WORD_BITS 32
#define ROUNDS 4
#define DEGREE 1
#define TAG_BITS 128
#define RATE_BYTES 40
#define RATE_WORDS 10

static void permute(cf_norx32_ctx *ctx)
{
#define G(a, b, c, d) \
  (a) = ((a) ^ (b)) ^ (((a) & (b)) << 1); \
  (d) = rotr32((a) ^ (d), 8); \
  (c) = ((c) ^ (d)) ^ (((c) & (d)) << 1); \
  (b) = rotr32((b) ^ (c), 11); \
  (a) = ((a) ^ (b)) ^ (((a) & (b)) << 1); \
  (d) = rotr32((a) ^ (d), 16); \
  (c) = ((c) ^ (d)) ^ (((c) & (d)) << 1); \
  (b) = rotr32((b) ^ (c), 31);

  for (int i = 0; i < ROUNDS; i++)
  {
    /* columns */
    G(ctx->s[0], ctx->s[4], ctx->s[8], ctx->s[12]);
    G(ctx->s[1], ctx->s[5], ctx->s[9], ctx->s[13]);
    G(ctx->s[2], ctx->s[6], ctx->s[10], ctx->s[14]);
    G(ctx->s[3], ctx->s[7], ctx->s[11], ctx->s[15]);

    /* diagonals */
    G(ctx->s[0], ctx->s[5], ctx->s[10], ctx->s[15]);
    G(ctx->s[1], ctx->s[6], ctx->s[11], ctx->s[12]);
    G(ctx->s[2], ctx->s[7], ctx->s[8], ctx->s[13]);
    G(ctx->s[3], ctx->s[4], ctx->s[9], ctx->s[14]);
  }
}

static void init(cf_norx32_ctx *ctx,
                 const uint8_t key[static 16],
                 const uint8_t nonce[static 8])
{
  /* 1. Basic setup */
  ctx->s[0] = 0x243f6a88;
  ctx->s[1] = read32_le(nonce + 0);
  ctx->s[2] = read32_le(nonce + 4);
  ctx->s[3] = 0x85a308d3;

  ctx->s[4] = read32_le(key + 0);
  ctx->s[5] = read32_le(key + 4);
  ctx->s[6] = read32_le(key + 8);
  ctx->s[7] = read32_le(key + 12);

  ctx->s[8]  = 0x13198a2e;
  ctx->s[9]  = 0x03707344;
  ctx->s[10] = 0x254f537a;
  ctx->s[11] = 0x38531d48;

  ctx->s[12] = 0x839c6e83;
  ctx->s[13] = 0xf97a3ae5;
  ctx->s[14] = 0x8c91d88c;
  ctx->s[15] = 0x11eafB59;

  /* 2. Parameter integration
   * R = 4
   * D = 1
   * W = 32
   * |A| = 128
   */
  ctx->s[14] ^= (ROUNDS << 26) ^ (DEGREE << 18) ^ (WORD_BITS << 10) ^ TAG_BITS;
  permute(ctx);
}

/* Input domain separation constant for next step, and final permutation of
 * preceeding step. */
static void switch_domain(cf_norx32_ctx *ctx, uint32_t constant)
{
  ctx->s[15] ^= constant;
  permute(ctx);
}

typedef struct
{
  cf_norx32_ctx *ctx;
  uint32_t type;
} blockctx;

static void input_block_final(void *vctx, const uint8_t *data)
{
  blockctx *bctx = vctx;
  cf_norx32_ctx *ctx = bctx->ctx;

  /* just xor-in data. */
  for (int i = 0; i < RATE_WORDS; i++)
  {
    ctx->s[i] ^= read32_le(data);
    data += WORD_BYTES;
  }
}

static void input_block(void *vctx, const uint8_t *data)
{
  /* Process block, then prepare for the next one. */
  blockctx *bctx = vctx;
  input_block_final(vctx, data);
  switch_domain(bctx->ctx, bctx->type);
}

static void input(cf_norx32_ctx *ctx, uint32_t type,
                  const uint8_t *buf, size_t nbuf)
{
  uint8_t partial[RATE_BYTES];
  size_t npartial = 0;
  blockctx bctx = { ctx, type };

  /* Process input. */
  cf_blockwise_accumulate(partial, &npartial, sizeof partial,
                          buf, nbuf,
                          input_block,
                          &bctx);

  /* Now pad partial. This contains the trailing portion of buf. */
  memset(partial + npartial, 0, sizeof(partial) - npartial);
  partial[npartial] = 0x01;
  partial[sizeof(partial) - 1] ^= 0x80;

  input_block_final(&bctx, partial);
}

static void do_header(cf_norx32_ctx *ctx, const uint8_t *buf, size_t nbuf)
{
  if (nbuf)
  {
    switch_domain(ctx, DOMAIN_HEADER);
    input(ctx, DOMAIN_HEADER, buf, nbuf);
  }
}

static void do_trailer(cf_norx32_ctx *ctx, const uint8_t *buf, size_t nbuf)
{
  if (nbuf)
  {
    switch_domain(ctx, DOMAIN_TRAILER);
    input(ctx, DOMAIN_TRAILER, buf, nbuf);
  }
}

static void body_block_encrypt(cf_norx32_ctx *ctx,
                               const uint8_t plain[static RATE_BYTES],
                               uint8_t cipher[static RATE_BYTES])
{
  for (int i = 0; i < RATE_WORDS; i++)
  {
    ctx->s[i] ^= read32_le(plain);
    write32_le(ctx->s[i], cipher);
    plain += WORD_BYTES;
    cipher += WORD_BYTES;
  }
}

static void encrypt_body(cf_norx32_ctx *ctx,
                         const uint8_t *plain, uint8_t *cipher, size_t nbytes)
{
  if (nbytes == 0)
    return;

  /* Process full blocks: easy */
  while (nbytes >= RATE_BYTES)
  {
    switch_domain(ctx, DOMAIN_PAYLOAD);
    body_block_encrypt(ctx, plain, cipher);
    plain += RATE_BYTES;
    cipher += RATE_BYTES;
    nbytes -= RATE_BYTES;
  }

  /* Final padded block. */
  uint8_t partial[RATE_BYTES];
  memset(partial, 0, sizeof partial);
  memcpy(partial, plain, nbytes);
  partial[nbytes] ^= 0x01;
  partial[sizeof(partial) - 1] ^= 0x80;

  switch_domain(ctx, DOMAIN_PAYLOAD);
  body_block_encrypt(ctx, partial, partial);

  memcpy(cipher, partial, nbytes);
}

static void body_block_decrypt(cf_norx32_ctx *ctx,
                               const uint8_t cipher[static RATE_BYTES],
                               uint8_t plain[static RATE_BYTES],
                               size_t start, size_t end)
{
  for (size_t i = start; i < end; i++)
  {
    uint32_t ct = read32_le(cipher);
    write32_le(ctx->s[i] ^ ct, plain);
    ctx->s[i] = ct;
    plain += WORD_BYTES;
    cipher += WORD_BYTES;
  }
}

static void undo_padding(cf_norx32_ctx *ctx, size_t bytes)
{
  assert(bytes < RATE_BYTES);
  ctx->s[bytes / WORD_BYTES] ^= 0x01 << ((bytes % WORD_BYTES) * 8);
  ctx->s[RATE_WORDS - 1] ^= 0x80000000;
}

static void decrypt_body(cf_norx32_ctx *ctx,
                         const uint8_t *cipher, uint8_t *plain, size_t nbytes)
{
  if (nbytes == 0)
    return;

  /* Process full blocks. */
  while (nbytes >= RATE_BYTES)
  {
    switch_domain(ctx, DOMAIN_PAYLOAD);
    body_block_decrypt(ctx, cipher, plain, 0, RATE_WORDS);
    plain += RATE_BYTES;
    cipher += RATE_BYTES;
    nbytes -= RATE_BYTES;
  }

  /* Then partial blocks. */
  size_t offset = 0;
  switch_domain(ctx, DOMAIN_PAYLOAD);

  undo_padding(ctx, nbytes);

  /* In units of whole words. */
  while (nbytes >= WORD_BYTES)
  {
    body_block_decrypt(ctx, cipher, plain, offset, offset + 1);
    plain += WORD_BYTES;
    cipher += WORD_BYTES;
    nbytes -= WORD_BYTES;
    offset += 1;
  }

  /* And then, finally, bytewise. */
  uint8_t tmp[WORD_BYTES];
  write32_le(ctx->s[offset], tmp);

  for (size_t i = 0; i < nbytes; i++)
  {
    uint8_t c = cipher[i];
    plain[i] = tmp[i] ^ c;
    tmp[i] = c;
  }

  ctx->s[offset] = read32_le(tmp);
}

static void get_tag(cf_norx32_ctx *ctx, uint8_t tag[static 16])
{
  switch_domain(ctx, DOMAIN_TAG);
  permute(ctx);
  write32_le(ctx->s[0], tag + 0);
  write32_le(ctx->s[1], tag + 4);
  write32_le(ctx->s[2], tag + 8);
  write32_le(ctx->s[3], tag + 12);
}

void cf_norx32_encrypt(const uint8_t key[static 16],
                       const uint8_t nonce[static 8],
                       const uint8_t *header, size_t nheader,
                       const uint8_t *plaintext, size_t nbytes,
                       const uint8_t *trailer, size_t ntrailer,
                       uint8_t *ciphertext,
                       uint8_t tag[static 16])
{
  cf_norx32_ctx ctx;

  init(&ctx, key, nonce);
  do_header(&ctx, header, nheader);
  encrypt_body(&ctx, plaintext, ciphertext, nbytes);
  do_trailer(&ctx, trailer, ntrailer);
  get_tag(&ctx, tag);

  mem_clean(&ctx, sizeof ctx);
}

int cf_norx32_decrypt(const uint8_t key[static 16],
                      const uint8_t nonce[static 8],
                      const uint8_t *header, size_t nheader,
                      const uint8_t *ciphertext, size_t nbytes,
                      const uint8_t *trailer, size_t ntrailer,
                      const uint8_t tag[static 16],
                      uint8_t *plaintext)
{
  cf_norx32_ctx ctx;
  uint8_t ourtag[16];

  init(&ctx, key, nonce);
  do_header(&ctx, header, nheader);
  decrypt_body(&ctx, ciphertext, plaintext, nbytes);
  do_trailer(&ctx, trailer, ntrailer);
  get_tag(&ctx, ourtag);

  int err = 0;

  if (!mem_eq(ourtag, tag, sizeof ourtag))
  {
    err = 1;
    mem_clean(plaintext, nbytes);
    mem_clean(ourtag, sizeof ourtag);
  }

  mem_clean(&ctx, sizeof ctx);
  return err;
}
