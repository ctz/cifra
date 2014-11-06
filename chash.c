#include "chash.h"
#include "handy.h"

#include <assert.h>

void cf_hash(const cf_chash *h, const void *m, size_t nm, uint8_t *out)
{
  cf_chash_ctx ctx;
  assert(h);
  h->init(&ctx);
  h->update(&ctx, m, nm);
  h->final(&ctx, out);
  mem_clean(&ctx, sizeof ctx);
}

