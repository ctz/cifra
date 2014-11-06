#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

/* Compute HMAC_hash(key, msg), writing the answer (which is
 * hash->hashsz to out. 
 * 
 * This function does not fail. */
void cf_hmac(const uint8_t *key, size_t nkey,
             const uint8_t *msg, size_t nmsg,
             uint8_t *out,
             const cf_chash *hash);

#endif
