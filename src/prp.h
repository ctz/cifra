#ifndef PRP_H
#define PRP_H

#include <stddef.h>
#include <stdint.h>

/**
 * General block cipher description
 * ================================
 * This allows us to implement block cipher modes which can work
 * with different block ciphers.
 */

/* .. c:type:: cf_prp_block
 * Block processing function type.
 *
 * The `in` and `out` blocks may alias.
 *
 * :rtype: void
 * :param ctx: block cipher-specific context object.
 * :param in: input block.
 * :param out: output block.
 */
typedef void (*cf_prp_block)(void *ctx, const uint8_t *in, uint8_t *out);

/* .. c:type:: cf_prp
 * Describes an PRP in a general way.
 *
 * .. c:member:: cf_prp.blocksz
 * Block size in bytes. Must be no more than :c:macro:`CF_MAXBLOCK`.
 *
 * .. c:member:: cf_prp.encrypt
 * Block encryption function.
 *
 * .. c:member:: cf_prp.decrypt
 * Block decryption function.
 */
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
