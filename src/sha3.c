#include <string.h>
#include <assert.h>

#include "sha3.h"
#include "blockwise.h"
#include "handy.h"
#include "bitops.h"

static const uint64_t round_constants[24] = {
  UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
  UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
  UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
  UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
  UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
  UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
  UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
  UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
  UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
  UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
  UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
  UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};

static const uint8_t rotation_constants[5][5] = {
  {  0,  1, 62, 28, 27, },
  { 36, 44,  6, 55, 20, },
  {  3, 10, 43, 25, 39, },
  { 41, 45, 15, 21,  8, },
  { 18,  2, 61, 56, 14, }
};

static void sha3_init(cf_sha3_context *ctx, uint16_t rate_bits, uint16_t capacity_bits)
{
  mem_clean(ctx, sizeof *ctx);
  ctx->rate = rate_bits / 8;
  ctx->capacity = capacity_bits / 8;
}

static void absorb(cf_sha3_context *ctx, const uint8_t *data, uint16_t sz)
{
  uint16_t lanes = sz / 8;

  for (uint16_t x = 0, y = 0, i = 0; i < lanes; i++)
  {
    ctx->A[x][y] ^= read64_le(data);
    data += 8;

    x++;
    if (x == 5)
    {
      y++;
      x = 0;
    }
  }
}

#define MOD5(x) ((x) < 0 ? (5 + (x)) : ((x) % 5))

static void theta(cf_sha3_context *ctx)
{
  uint64_t C[5], D[5];

  for (int x = 0; x < 5; x++)
    C[x] = ctx->A[x][0] ^ ctx->A[x][1] ^ ctx->A[x][2] ^ ctx->A[x][3] ^ ctx->A[x][4];

  for (int x = 0; x < 5; x++)
  {
    D[x] = C[MOD5(x - 1)] ^ rotl64(C[MOD5(x + 1)], 1);

    for (int y = 0; y < 5; y++)
      ctx->A[x][y] ^= D[x];
  }
}

static void rho_pi_chi(cf_sha3_context *ctx)
{
  uint64_t B[5][5] = { { 0 } };

  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++)
      B[y][MOD5(2 * x + 3 * y)] = rotl64(ctx->A[x][y], rotation_constants[y][x]);

  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++)
      ctx->A[x][y] = B[x][y] ^ ((~ B[MOD5(x + 1)][y]) & B[MOD5(x + 2)][y]);
}

static void permute(cf_sha3_context *ctx)
{
  for (int r = 0; r < 24; r++)
  {
    theta(ctx);
    rho_pi_chi(ctx);

    /* iota */
    ctx->A[0][0] ^= round_constants[r];
  }
}

static void extract(cf_sha3_context *ctx, uint8_t *out, size_t nbytes)
{
  uint16_t lanes = (nbytes + 7) / 8;

  for (uint16_t x = 0, y = 0, i = 0; i < lanes; i++)
  {
    if (nbytes >= 8)
    {
      write64_le(ctx->A[x][y], out);
      out += 8;
      nbytes -= 8;
    } else {
      uint8_t buf[8];
      write64_le(ctx->A[x][y], buf);
      memcpy(out, buf, nbytes);
      out += nbytes;
      nbytes = 0;
    }
    
    x++;
    if (x == 5)
    {
      y++;
      x = 0;
    }
  }
}

static void squeeze(cf_sha3_context *ctx, uint8_t *out, size_t nbytes)
{
  while (nbytes)
  {
    size_t take = MIN(nbytes, ctx->rate);
    extract(ctx, out, take);
    out += take;
    nbytes -= take;

    if (nbytes)
      permute(ctx);
  }
}

static void sha3_block(void *vctx, const uint8_t *data)
{
  cf_sha3_context *ctx = vctx;

  absorb(ctx, data, ctx->rate);
  permute(ctx);
}

static void sha3_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, ctx->rate,
                          data, nbytes,
                          sha3_block, ctx);
}

static void pad(cf_sha3_context *ctx, size_t npad)
{
  uint8_t byte;

  if (npad == 1)
  {
    byte = 0x81;
    sha3_update(ctx, &byte, 1);
    return;
  }

  /* add 0x01, 0x00, 0x00, ..., 0x80 */
  byte = 0x01;
  sha3_update(ctx, &byte, 1);
  npad--;

  byte = 0x00;
  while (--npad)
    sha3_update(ctx, &byte, 1);

  byte = 0x80;
  sha3_update(ctx, &byte, 1);
}

static void pad_and_squeeze(cf_sha3_context *ctx, uint8_t *out, size_t nout)
{
  pad(ctx, ctx->rate - ctx->npartial);
  assert(ctx->npartial == 0);

  squeeze(ctx, out, nout);
}

/* SHA3-224 */
void cf_sha3_224_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 1152, 448);
}

void cf_sha3_224_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_sha3_224_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_224_HASHSZ])
{
  cf_sha3_context ours = *ctx;
  cf_sha3_224_digest_final(&ours, hash);
}

void cf_sha3_224_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_224_HASHSZ])
{
  pad_and_squeeze(ctx, hash, CF_SHA3_224_HASHSZ);
}

const cf_chash cf_sha3_224 = {
  .hashsz = CF_SHA3_224_HASHSZ,
  .ctxsz = sizeof(cf_sha3_context),
  .blocksz = CF_SHA3_224_BLOCKSZ,
  .init = (cf_chash_init) cf_sha3_224_init,
  .update = (cf_chash_update) cf_sha3_224_update,
  .digest = (cf_chash_digest) cf_sha3_224_digest
};

/* SHA3-256 */
void cf_sha3_256_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 1088, 512);
}

void cf_sha3_256_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_sha3_256_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_256_HASHSZ])
{
  cf_sha3_context ours = *ctx;
  cf_sha3_256_digest_final(&ours, hash);
}

void cf_sha3_256_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_256_HASHSZ])
{
  pad_and_squeeze(ctx, hash, CF_SHA3_256_HASHSZ);
}

const cf_chash cf_sha3_256 = {
  .hashsz = CF_SHA3_256_HASHSZ,
  .ctxsz = sizeof(cf_sha3_context),
  .blocksz = CF_SHA3_256_BLOCKSZ,
  .init = (cf_chash_init) cf_sha3_256_init,
  .update = (cf_chash_update) cf_sha3_256_update,
  .digest = (cf_chash_digest) cf_sha3_256_digest
};

/* SHA3-384 */
void cf_sha3_384_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 832, 768);
}

void cf_sha3_384_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_sha3_384_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_384_HASHSZ])
{
  cf_sha3_context ours = *ctx;
  cf_sha3_384_digest_final(&ours, hash);
}

void cf_sha3_384_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_384_HASHSZ])
{
  pad_and_squeeze(ctx, hash, CF_SHA3_384_HASHSZ);
}

const cf_chash cf_sha3_384 = {
  .hashsz = CF_SHA3_384_HASHSZ,
  .ctxsz = sizeof(cf_sha3_context),
  .blocksz = CF_SHA3_384_BLOCKSZ,
  .init = (cf_chash_init) cf_sha3_384_init,
  .update = (cf_chash_update) cf_sha3_384_update,
  .digest = (cf_chash_digest) cf_sha3_384_digest
};

/* SHA3-512 */
void cf_sha3_512_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 576, 1024);
}

void cf_sha3_512_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_sha3_512_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_512_HASHSZ])
{
  cf_sha3_context ours = *ctx;
  cf_sha3_512_digest_final(&ours, hash);
}

void cf_sha3_512_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_512_HASHSZ])
{
  pad_and_squeeze(ctx, hash, CF_SHA3_512_HASHSZ);
}

const cf_chash cf_sha3_512 = {
  .hashsz = CF_SHA3_512_HASHSZ,
  .ctxsz = sizeof(cf_sha3_context),
  .blocksz = CF_SHA3_512_BLOCKSZ,
  .init = (cf_chash_init) cf_sha3_512_init,
  .update = (cf_chash_update) cf_sha3_512_update,
  .digest = (cf_chash_digest) cf_sha3_512_digest
};
