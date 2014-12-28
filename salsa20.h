#ifndef SALSA20_H
#define SALSA20_H

#include <stdint.h>
#include <stddef.h>

void cf_salsa20_core(const uint8_t key0[16],
                     const uint8_t key1[16],
                     const uint8_t nonce[16],
                     const uint8_t sigma[16],
                     uint8_t out[64]);

#endif
