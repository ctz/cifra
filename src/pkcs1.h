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
 * For encryption this provides RSAES-OAEP and RSAES-PKCS1-v1_5
 * (the latter is broken and use is strongly discouraged).
 *
 * For signatures this provides RSASSA-PSS and RSASSA-PKSC1-v1_5
 * (the latter is obsolete and use is strongly discouraged).
 */

unsigned cf_rsaes_oaep_can_encode(const cf_chash *hash,
                                  size_t nmessage, size_t nmodulus);

void cf_rsaes_oaep_encode(const cf_chash *hash, cf_rng *rng,
                          const uint8_t *message, size_t nmessage,
                          uint8_t *enc_out, size_t nmodulus);

/* message_out must be nmodulus bytes, *nmessage contains the valid
 * prefix of the message. */
unsigned cf_rsaes_oaep_decode(const cf_chash *hash,
                              const uint8_t *enc, size_t nmodulus,
                              uint8_t *message_out, size_t *nmessage);

unsigned cf_rsaes_pkcs1_can_encode(size_t nmessage, size_t nmodulus);

void cf_rsaes_pkcs1_encode(cf_rng *rng,
                           const uint8_t *message, size_t nmessage,
                           uint8_t *enc_out, size_t nmodulus);

unsigned cf_rsaes_pkcs1_decode(const uint8_t *enc, size_t nmodulus,
                               uint8_t *message_out, size_t *nmessage);

unsigned cf_rsassa_pkcs1_can_encode(size_t nmessage, size_t nmodulus);

void cf_rsassa_pkcs1_encode(const uint8_t *message, size_t nmessage,
                            uint8_t *enc_out, size_t nmodulus);

unsigned cf_rsassa_pkcs1_verify(const uint8_t *enc, size_t nmodulus,
                                const uint8_t *message, size_t nmessage);

unsigned cf_rsassa_pss_can_encode(const cf_chash *hash, size_t nmodulus);

/* nb. fixes sLen = hLen */
void cf_rsassa_pss_encode(const cf_chash *hash, cf_rng *rng,
                          const uint8_t *msghash, /* of size hash->hashsz */
                          uint8_t *enc_out, size_t nmodulus);

unsigned cf_rsassa_pss_verify(const cf_chash *hash,
                              const uint8_t *msghash,
                              const uint8_t *enc, size_t nmodulus);

#endif
