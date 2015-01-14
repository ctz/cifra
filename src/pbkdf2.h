#ifndef PBKDF2_H
#define PBKDF2_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

void cf_pbkdf2_hmac(const uint8_t *pw, size_t npw,
                    const uint8_t *salt, size_t nsalt,
                    uint32_t iterations,
                    uint8_t *out, size_t nout,
                    const cf_chash *hash);

#endif
