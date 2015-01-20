/**
 * @brief Operations in GF(2^128).
 *
 * These implementations are constant time, but relatively slow.
 */

#ifndef GF128_H
#define GF128_H

#include <stddef.h>
#include <stdint.h>

/* out = 2 * in.  Arguments may not alias. */
void cf_gf128_double(const uint8_t in[16], uint8_t out[16]);

/* out = 2 * in.  Arguments may not alias. 
 * This differs from cf_gf128_double because it interprets the
 * block in little endian: the lsb is the msb of the 
 * first element, the msb is the lsb of the last element.
 *
 * GCM uses this convention. */
void cf_gf128_double_le(const uint8_t in[16], uint8_t out[16]);

/* out = x + y.  Arguments may alias. */
void cf_gf128_add(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]);

/* out = xy.  Arguments may alias.
 *
 * This uses cf_gf128_double_le internally, and is suitable for
 * GCM. */
void cf_gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]);

#endif
