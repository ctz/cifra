#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
  uint32_t h[17];       /* current accumulator */
  uint32_t r[17];       /* multiplier */
  uint8_t s[16];        /* final offset */
  uint8_t partial[16];  /* partial block buffer */
  size_t npartial;      /* block buffer usage */
} cf_poly1305;

/* Initialise context.
 * r is the block multiplier.
 * s is the final offset. */
void cf_poly1305_init(cf_poly1305 *ctx,
                      const uint8_t r[static 16],
                      const uint8_t s[static 16]);

/* Process data at buf. */
void cf_poly1305_update(cf_poly1305 *ctx,
                        const uint8_t *buf,
                        size_t nbytes);

/* Finish: write MAC to out, trash ctx. */
void cf_poly1305_finish(cf_poly1305 *ctx,
                        uint8_t out[static 16]);

#endif
