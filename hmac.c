#include "hmac.h"
#include "chash.h"
#include "handy.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

static void xor(uint8_t *out, const uint8_t *in, uint8_t d, size_t len)
{
  for (size_t i = 0; i < len; i++)
    out[i] = in[i] ^ d;
}

void cf_hmac(const uint8_t *key, size_t nkey,
             const uint8_t *msg, size_t nmsg,
             uint8_t *out,
             const cf_chash *hash)
{
  assert(nkey || !key);
  assert(nmsg || !msg);
  assert(out);
  assert(hash);

  assert(CF_MAXHASH <= CF_CHASH_MAXBLK);

  uint8_t k[CF_CHASH_MAXBLK];

  /* Shorten long keys. */
  if (nkey > hash->blocksz)
  {
    cf_hash(hash, key, nkey, k);
    key = k;
    nkey = hash->hashsz;
  }

  /* Right zero-pad short keys. */
  if (nkey < hash->blocksz)
  {
    if (k != key)
      memcpy(k, key, nkey);
    memset(k + nkey, 0, hash->blocksz - nkey);
  } else {
    /* Or just copy in. */
    if (k != key)
      memcpy(k, key, nkey);
  }

  uint8_t blk[CF_CHASH_MAXBLK];
  uint8_t inner[CF_MAXHASH];
  cf_chash_ctx ctx;

  /* Inner block */
  xor(blk, k, 0x36, hash->blocksz);
  hash->init(&ctx);
  hash->update(&ctx, blk, hash->blocksz);
  hash->update(&ctx, msg, nmsg);
  hash->final(&ctx, inner);

  /* Outer block */
  xor(blk, k, 0x5c, hash->blocksz);
  hash->init(&ctx);
  hash->update(&ctx, blk, hash->blocksz);
  hash->update(&ctx, inner, hash->hashsz);
  hash->final(&ctx, out);

  mem_clean(inner, sizeof inner);
  mem_clean(blk, sizeof blk);
  mem_clean(&ctx, sizeof ctx);
  mem_clean(k, sizeof k);
}

