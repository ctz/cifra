/**
 * @brief Operations in GF(2^128).
 *
 * These implementations are constant time, but relatively slow.
 */

#ifndef GF128_H
#define GF128_H

#include <stddef.h>
#include <stdint.h>

typedef uint32_t cf_gf128[4];

/* Unpack from big-endian bytes into out. */
void cf_gf128_frombytes_be(const uint8_t in[16], cf_gf128 out);

/* Pack in big-endian order into out. */
void cf_gf128_tobytes_be(const cf_gf128 in, uint8_t out[16]);

/* out = 2 * in.  Arguments may not alias. */
void cf_gf128_double(const cf_gf128 in, cf_gf128 out);

/* out = 2 * in.  Arguments may not alias. 
 * This differs from cf_gf128_double because it interprets the
 * block in little endian: the lsb is the msb of the 
 * first element, the msb is the lsb of the last element.
 *
 * GCM uses this convention. */
void cf_gf128_double_le(const cf_gf128 in, cf_gf128 out);

/* out = x + y.  Arguments may alias. */
void cf_gf128_add(const cf_gf128 x, const cf_gf128 y, cf_gf128 out);

/* out = xy.  Arguments may alias.
 *
 * This uses cf_gf128_double_le internally, and is suitable for
 * GCM. */
void cf_gf128_mul(const cf_gf128 x, const cf_gf128 y, cf_gf128 out);

#endif
