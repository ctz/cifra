#include "blockwise.h"
#include "handy.h"

#include <assert.h>
#include <string.h>

void cf_blockwise_accumulate(uint8_t *partial, size_t *npartial, size_t nblock,
                             const void *inp, size_t nbytes,
                             cf_blockwise_fn process, void *ctx)
{
  const uint8_t *bufin = inp;
  assert(partial && *npartial < nblock);
  assert(inp || !nbytes);
  assert(process && ctx);

  /* If we have partial data, copy in to buffer. */
  if (*npartial)
  {
    size_t space = nblock - *npartial;
    size_t taken = MIN(space, nbytes);

    memcpy(partial + *npartial, bufin, taken);

    bufin += taken;
    nbytes -= taken;
    *npartial += taken;

    /* If that gives us a full block, process it. */
    if (*npartial == nblock)
    {
      process(ctx, partial);
      *npartial = 0;
    }
  }

  /* now nbytes < nblock or *npartial == 0. */

  /* If we have a full block of data, process it directly. */
  while (nbytes >= nblock)
  {
    /* Partial buffer must be empty, or we're ignoring extant data */
    assert(*npartial == 0);

    process(ctx, bufin);
    bufin += nblock;
    nbytes -= nblock;
  }

  /* Finally, if we have remaining data, buffer it. */
  while (nbytes)
  {
    size_t space = nblock - *npartial;
    size_t taken = MIN(space, nbytes);

    memcpy(partial + *npartial, bufin, taken);

    bufin += taken;
    nbytes -= taken;
    *npartial += taken;

    if (*npartial == nblock)
    {
      process(ctx, partial);
      *npartial = 0;
    }
  }
}
