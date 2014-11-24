#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "sha2.h"
#include "blockwise.h"
#include "bitops.h"
#include "handy.h"

static const uint64_t K[80] = {
  UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
  UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
  UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
  UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
  UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
  UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
  UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
  UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
  UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
  UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
  UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
  UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
  UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
  UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
  UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
  UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
  UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
  UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
  UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
  UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
  UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
  UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
  UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
  UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
  UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
  UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
  UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
  UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
  UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
  UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
  UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
  UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
  UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
  UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
  UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
  UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
  UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
  UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
  UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
  UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817)
};

static inline uint64_t CH(uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ (~x & z);
}

static inline uint64_t MAJ(uint64_t x, uint64_t y, uint64_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint64_t BSIG0(uint64_t x)
{
  return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

static inline uint64_t BSIG1(uint64_t x)
{
  return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

static inline uint64_t SSIG0(uint64_t x)
{
  return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

static inline uint64_t SSIG1(uint64_t x)
{
  return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

void cf_sha512_init(cf_sha512_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = UINT64_C(0x6a09e667f3bcc908);
  ctx->H[1] = UINT64_C(0xbb67ae8584caa73b);
  ctx->H[2] = UINT64_C(0x3c6ef372fe94f82b);
  ctx->H[3] = UINT64_C(0xa54ff53a5f1d36f1);
  ctx->H[4] = UINT64_C(0x510e527fade682d1);
  ctx->H[5] = UINT64_C(0x9b05688c2b3e6c1f);
  ctx->H[6] = UINT64_C(0x1f83d9abfb41bd6b);
  ctx->H[7] = UINT64_C(0x5be0cd19137e2179);
}

void cf_sha384_init(cf_sha512_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = UINT64_C(0xcbbb9d5dc1059ed8);
  ctx->H[1] = UINT64_C(0x629a292a367cd507);
  ctx->H[2] = UINT64_C(0x9159015a3070dd17);
  ctx->H[3] = UINT64_C(0x152fecd8f70e5939);
  ctx->H[4] = UINT64_C(0x67332667ffc00b31);
  ctx->H[5] = UINT64_C(0x8eb44a8768581511);
  ctx->H[6] = UINT64_C(0xdb0c2e0d64f98fa7);
  ctx->H[7] = UINT64_C(0x47b5481dbefa4fa4);
}

static void sha512_update_block(void *vctx, const uint8_t *inp)
{
  cf_sha512_context *ctx = vctx;

  uint64_t W[80];

  for (size_t t = 0; t < 16; t++)
  {
    W[t] = read64_be(inp);
    inp += 8;
  }

  for (size_t t = 16; t < 80; t++)
  {
    W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
  }

  uint64_t a = ctx->H[0],
           b = ctx->H[1],
           c = ctx->H[2],
           d = ctx->H[3],
           e = ctx->H[4],
           f = ctx->H[5],
           g = ctx->H[6],
           h = ctx->H[7];

  for (size_t t = 0; t < 80; t++)
  {
    uint64_t T1 = h + BSIG1(e) + CH(e, f, g) + K[t] + W[t];
    uint64_t T2 = BSIG0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  ctx->H[0] += a;
  ctx->H[1] += b;
  ctx->H[2] += c;
  ctx->H[3] += d;
  ctx->H[4] += e;
  ctx->H[5] += f;
  ctx->H[6] += g;
  ctx->H[7] += h;

  ctx->blocks++;
}

void cf_sha512_update(cf_sha512_context *ctx, const void *data, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                          data, nbytes,
                          sha512_update_block, ctx);
}

void cf_sha384_update(cf_sha512_context *ctx, const void *data, size_t nbytes)
{
  cf_sha512_update(ctx, data, nbytes);
}

void cf_sha512_final(const cf_sha512_context *ctx, uint8_t hash[CF_SHA512_HASHSZ])
{
  /* We copy the context, so the finalisation doesn't effect the caller's
   * context.  This means the caller can do:
   *
   * x = init()
   * x.update('hello')
   * h1 = x.final()
   * x.update(' world')
   * h2 = x.final()
   *
   * to get h1 = H('hello') and h2 = H('hello world')
   *
   * This wouldn't work if we applied MD-padding to *ctx.
   */

  cf_sha512_context ours = *ctx;
  uint8_t padbuf[CF_SHA512_BLOCKSZ];

  uint64_t digested_bytes = ours.blocks;
  digested_bytes = digested_bytes * CF_SHA512_BLOCKSZ + ours.npartial;
  uint64_t digested_bits = digested_bytes * 8;

  size_t zeroes = CF_SHA512_BLOCKSZ - ((digested_bytes + 1 + 16) % CF_SHA512_BLOCKSZ);

  /* Hash 0x80 00 ... block first. */
  padbuf[0] = 0x80;
  memset(padbuf + 1, 0, zeroes);
  cf_sha512_update(&ours, padbuf, 1 + zeroes);

  /* Now hash length. */
  write64_be(0, padbuf);
  write64_be(digested_bits, padbuf + 8);
  cf_sha512_update(&ours, padbuf, 16);

  /* We ought to have got our padding calculation right! */
  assert(ours.npartial == 0);

  write64_be(ours.H[0], hash + 0);
  write64_be(ours.H[1], hash + 8);
  write64_be(ours.H[2], hash + 16);
  write64_be(ours.H[3], hash + 24);
  write64_be(ours.H[4], hash + 32);
  write64_be(ours.H[5], hash + 40);
  write64_be(ours.H[6], hash + 48);
  write64_be(ours.H[7], hash + 56);
}

void cf_sha384_final(const cf_sha512_context *ctx, uint8_t hash[CF_SHA384_HASHSZ])
{
  uint8_t full[CF_SHA512_HASHSZ];
  cf_sha512_final(ctx, full);
  memcpy(hash, full, CF_SHA384_HASHSZ);
}

const cf_chash cf_sha384 = {
  .hashsz = CF_SHA384_HASHSZ,
  .ctxsz = sizeof(cf_sha512_context),
  .blocksz = CF_SHA384_BLOCKSZ,
  .init = (cf_chash_init) cf_sha384_init,
  .update = (cf_chash_update) cf_sha384_update,
  .final = (cf_chash_final) cf_sha384_final
};

const cf_chash cf_sha512 = {
  .hashsz = CF_SHA512_HASHSZ,
  .ctxsz = sizeof(cf_sha512_context),
  .blocksz = CF_SHA512_BLOCKSZ,
  .init = (cf_chash_init) cf_sha512_init,
  .update = (cf_chash_update) cf_sha512_update,
  .final = (cf_chash_final) cf_sha512_final
};

