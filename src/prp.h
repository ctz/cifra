#ifndef PRP_H
#define PRP_H

#include <stddef.h>
#include <stdint.h>

/* Block processing function. in and out may alias. */
typedef void (*cf_prp_block)(void *ctx, const uint8_t *in, uint8_t *out);

/* Describes an PRP in a general way. */
typedef struct
{
  size_t blocksz;
  cf_prp_block encrypt;
  cf_prp_block decrypt;
} cf_prp;

/* .. c:macro:: CF_MAXBLOCK
 * The maximum block cipher blocksize we support, in bytes.
 */
#define CF_MAXBLOCK 16

#endif
