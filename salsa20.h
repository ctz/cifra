#ifndef SALSA20_H
#define SALSA20_H

#include <stdint.h>
#include <stddef.h>

void cf_salsa20_core(const uint8_t key0[16],
                     const uint8_t key1[16],
                     const uint8_t nonce[16],
                     const uint8_t sigma[16],
                     uint8_t out[64]);
                     
void cf_chacha20_core(const uint8_t key0[16],
                      const uint8_t key1[16],
                      const uint8_t nonce[16],
                      const uint8_t sigma[16],
                      uint8_t out[64]);

typedef struct
{
  uint8_t key0[16], key1[16];
  uint8_t nonce[16];
  const uint8_t *sigma;
  uint8_t block[64];
  size_t nblock;
} cf_salsa20_ctx, cf_chacha20_ctx;

void cf_salsa20_init(cf_salsa20_ctx *ctx, const uint8_t *key, size_t nkey, uint8_t nonce[8]);
void cf_chacha20_init(cf_chacha20_ctx *ctx, const uint8_t *key, size_t nkey, uint8_t nonce[8]);

void cf_salsa20_cipher(cf_salsa20_ctx *ctx, const uint8_t *input, uint8_t *output, size_t bytes);
void cf_chacha20_cipher(cf_chacha20_ctx *ctx, const uint8_t *input, uint8_t *output, size_t bytes);

#endif
