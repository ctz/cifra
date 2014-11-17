
#include "pbkdf2.h"
#include "hmac.h"
#include "bitops.h"
#include "handy.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

static void F(const cf_hmac_ctx *startctx,
              uint32_t counter,
              const uint8_t *salt, size_t nsalt,
              uint32_t iterations,
              uint8_t *out)
{
  uint8_t U[CF_MAXHASH];
  size_t hashsz = startctx->hash->hashsz;
  
  uint8_t countbuf[4];
  write32_be(counter, countbuf);

  /* First iteration:
   *   U_1 = PRF(P, S || INT_32_BE(i))
   */
  cf_hmac_ctx ctx = *startctx;
  cf_hmac_update(&ctx, salt, nsalt);
  cf_hmac_update(&ctx, countbuf, sizeof countbuf);
  cf_hmac_finish(&ctx, U);
  memcpy(out, U, hashsz);

  /* Subsequent iterations:
   *   U_c = PRF(P, U_{c-1})
   */
  for (uint32_t i = 1; i < iterations; i++)
  {
    ctx = *startctx;
    cf_hmac_update(&ctx, U, hashsz);
    cf_hmac_finish(&ctx, U);
    xor_bb(out, out, U, hashsz);
  }
}

void cf_pbkdf2_hmac(const uint8_t *pw, size_t npw,
                    const uint8_t *salt, size_t nsalt,
                    uint32_t iterations,
                    uint8_t *out, size_t nout,
                    const cf_chash *hash)
{
  uint32_t counter = 1;
  uint8_t block[CF_MAXHASH];

  assert(iterations);
  assert(out && nout);
  assert(hash);

  /* Starting point for inner loop. */
  cf_hmac_ctx ctx;
  cf_hmac_init(&ctx, hash, pw, npw);

  while (nout)
  {
    F(&ctx, counter, salt, nsalt, iterations, block);

    size_t taken = MIN(nout, hash->hashsz);
    memcpy(out, block, taken);
    out += taken;
    nout -= taken;
    counter++;
  }
}

