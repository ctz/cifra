#ifndef BLOCKWISE_H
#define BLOCKWISE_H

#include <stdint.h>
#include <stddef.h>

/* Processing function for blockwise_accumulate. */
typedef void (*cf_blockwise_fn)(void *ctx, const uint8_t *data);

/* This function manages the common abstraction of accumulating input in
 * a buffer, and processing it when a full block is available.
 *
 * partial is the buffer (maintained by the caller)
 * on entry, npartial is the currently valid count of used bytes on
 *   the front of partial.
 * on exit, npartial is updated to reflect the status of partial.
 * nblock is the blocksize to accumulate -- partial must be at least
 *   this long!
 * input is the new data to process, of length nbytes.
 * process is the processing function, passed ctx and a pointer
 *   to the data to process (always exactly nblock bytes long!)
 *   which may not neccessarily be the same as partial.
 */
void cf_blockwise_accumulate(uint8_t *partial, size_t *npartial,
                             size_t nblock,
                             const void *input, size_t nbytes,
                             cf_blockwise_fn process, void *ctx);

#endif
