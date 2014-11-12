#ifndef PRP_H
#define PRP_H

#include <stddef.h>
#include <stdint.h>

typedef enum
{
  cf_prp_encrypt,
  cf_prp_decrypt
} cf_prp_encdec;

/* Block processing function. in and out may alias. */
typedef void (*cf_prp_block)(void *ctx, cf_prp_encdec encdec, const uint8_t *in, uint8_t *out);

/* Describes an PRP in a general way. */
typedef struct
{
  size_t blocksz;
  cf_prp_block block;
} cf_prp;

#define CF_MAXBLOCK 16

#endif
