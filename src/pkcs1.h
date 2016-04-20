/*
 * cifra - embedded cryptography library
 * Written in 2016 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef PKCS1_H
#define PKCS1_H

#include <stdint.h>
#include <stddef.h>

#include "chash.h"
#include "rng.h"

/**
 * PKCS#1 encryption and signature padding
 * =======================================
 * This is an implementation of PKCS#1/RFC3447 for RSA.
 *
 * For encryption this provides `RSAES-OAEP` and `RSAES-PKCS1-v1_5`.
 * `RSAES-PKCS-v1_5` is *broken*, do not use it.
 *
 * For signatures this provides `RSASSA-PSS` and `RSASSA-PKCS1-v1_5`.
 * Use of `RSASSA-PKCS1-v1_5` is discouraged.
 */

/**
 * OAEP
 * ----
 */

/* .. c:function:: $DECL
 * For a given modulus size `nmodulus` in bytes, returns non-zero
 * if a message of size `nmessage` in bytes can be encoded.
 * `hash` describes the hash function used by MGF1. */
unsigned cf_rsaes_oaep_can_encode(const cf_chash *hash,
                                  size_t nmessage, size_t nmodulus);

/* .. c:function:: $DECL
 * OAEP encoding: encodes the given `message` of length
 * `nmessage` bytes.
 *
 * `rng` provides random material, and internally MGF1 uses
 * `hash`.  The result is written to `enc_out` of length
 * `nmodulus` bytes.
 *
 * :c:func:`cf_rsaes_oaep_can_encode` must return non-zero
 * for the arguments as a prerequisite for this function. */
void cf_rsaes_oaep_encode(const cf_chash *hash, cf_rng *rng,
                          const uint8_t *message, size_t nmessage,
                          uint8_t *enc_out, size_t nmodulus);

/* .. c:function:: $DECL
 * OAEP decoding: decodes the alleged OAEP encoding at `enc` of
 * `nmodulus` bytes, writing the result to `message_out` and its
 * length to `nmessage`.  `message_out` must point to at least
 * `nmodulus` bytes.
 *
 * Returns non-zero if the encoding is invalid: `nmessage` and
 * `message_out` will be undefined values but must not be used.
 * Returns zero on success.
 */
unsigned cf_rsaes_oaep_decode(const cf_chash *hash,
                              const uint8_t *enc, size_t nmodulus,
                              uint8_t *message_out, size_t *nmessage);

/**
 * PKCS#1 encryption encoding
 * --------------------------
 */

/* .. c:function:: $DECL
 * For a given modulus size `nmodulus` in bytes, returns non-zero
 * if a message of size `nmessage` can be encoded. */
unsigned cf_rsaes_pkcs1_can_encode(size_t nmessage, size_t nmodulus);

/* .. c:function:: $DECL
 * PKCS#1 encryption encoding: encodes the given `message` of
 * length `nmessage`, writing the encoding to `enc_out` of size
 * `nmodulus` bytes.
 *
 * `rng` provides random material. */
void cf_rsaes_pkcs1_encode(cf_rng *rng,
                           const uint8_t *message, size_t nmessage,
                           uint8_t *enc_out, size_t nmodulus);

/* .. c:function:: $DECL
 * PKCS#1 encryption decoding: decodes `enc` of size `nmodulus` bytes,
 * writing the result to `message_out` and its length to `nmessage`.
 * `message_out` must be at least `nmodulus` bytes.
 *
 * Returns non-zero if the encoding is invalid, or zero if it was OK.
 * This encoding is fundamentally unsafe; use OAEP instead if you can. */
unsigned cf_rsaes_pkcs1_decode(const uint8_t *enc, size_t nmodulus,
                               uint8_t *message_out, size_t *nmessage);

/**
 * PKCS#1 signature encoding
 * -------------------------
 */

/* .. c:function:: $DECL
 * For a given modulus size `nmodulus` in bytes, returns non-zero
 * if a message of size `nmessage` can be encoded. */
unsigned cf_rsassa_pkcs1_can_encode(size_t nmessage, size_t nmodulus);

/* .. c:function:: $DECL
 * PKCS#1 signature encoding: encodes `message` of size `nmessage`
 * bytes, writing the encoding to `enc_out` of size `nmodulus` bytes.
 *
 * Note that this function does not hash the message or encode the hash
 * in a DigestInfo ASN.1 structure. */
void cf_rsassa_pkcs1_encode(const uint8_t *message, size_t nmessage,
                            uint8_t *enc_out, size_t nmodulus);

/* .. c:function:: $DECL
 * PKCS#1 signature verification: returns zero if the encoding of
 * `message` of size `nmessage` bytes is the same as the given encoding
 * `enc` of size `nmodulus` bytes. */
unsigned cf_rsassa_pkcs1_verify(const uint8_t *enc, size_t nmodulus,
                                const uint8_t *message, size_t nmessage);

/**
 * PSS signature encoding
 * ----------------------
 * This implementation fixes the salt length equal to the hash function
 * output length, and the MGF hash the same as the message hash.
 */

/* .. c:function:: $DECL
 * For a given modulus size `nmodulus` given the hash function `hash`
 * (used both for the MGF and message hash). */
unsigned cf_rsassa_pss_can_encode(const cf_chash *hash, size_t nmodulus);

/* .. c:function:: $DECL
 * PSS signature encoding: encodes the given `msghash` of length
 * `hash->hashsz` bytes, writing the encoding to `enc_out` of
 * length `nmodulus` bytes.  `hash` is used internally as well
 * as being the hash used to produce `msghash`.  `rng` is
 * used to obtain entropy. */
void cf_rsassa_pss_encode(const cf_chash *hash, cf_rng *rng,
                          const uint8_t *msghash,
                          uint8_t *enc_out, size_t nmodulus);

/* .. c:function:: $DECL
 * PSS signature verification: decodes the encoding `enc` of length
 * `nmodulus` bytes using `hash` and checks it matches the message
 * hash `msghash` of length `hash->hashsz` bytes.
 *
 * Returns non-zero if the signature is invalid, zero if it is OK. */
unsigned cf_rsassa_pss_verify(const cf_chash *hash,
                              const uint8_t *msghash,
                              const uint8_t *enc, size_t nmodulus);

#endif
