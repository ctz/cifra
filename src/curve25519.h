#ifndef CURVE25519_H
#define CURVE25519_H

#include <stddef.h>
#include <stdint.h>

/**
 * Curve25519
 * ==========
 * This is `curve25519 <http://cr.yp.to/ecdh.html>`_ with switchable
 * implementations underneath.
 *
 * By default tweetnacl is used.
 */

/* .. c:function:: $DECL
 * Multiplies `point` by `scalar`, putting the resulting point into `out`. */
void cf_curve25519_mul(uint8_t out[32],
                       const uint8_t scalar[32],
                       const uint8_t point[32]);

/* .. c:function:: $DECL
 * Multiplies `scalar` by the curve25519 base point, putting the resulting
 * point into `out`. */
void cf_curve25519_mul_base(uint8_t out[32], const uint8_t scalar[32]);

#endif
