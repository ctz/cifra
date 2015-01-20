
#include "gf128.h"
#include "bitops.h"

#include <string.h>

/* out = 2 * in.  Arguments may alias. */
void cf_gf128_double(const uint8_t in[16], uint8_t out[16])
{
  uint8_t table[2] = { 0x00, 0x87 };
  uint8_t topbyte = in[0];
  uint8_t borrow = 0;
  
  for (size_t i = 16; i != 0; i--)
  {
    uint8_t inbyte = in[i - 1];
    out[i - 1] = (inbyte << 1) | borrow;
    borrow = inbyte >> 7;
  }

  out[15] ^= select_u8(!!(topbyte & 0x80), table, 2);
}

/* out = 2 * in.  Arguments may alias. */
void cf_gf128_double_le(const uint8_t in[16], uint8_t out[16])
{
  uint8_t table[2] = { 0x00, 0xe1 };
  uint8_t topbyte = in[15];
  uint8_t borrow = 0;

  for (size_t i = 0; i < 16; i++)
  {
    uint8_t inbyte = in[i];
    out[i] = (inbyte >> 1) | (borrow << 7);
    borrow = inbyte & 1;
  }

  out[0] ^= select_u8(!!(topbyte & 1), table, 2);
}

/* out = x + y.  Arguments may alias. */
void cf_gf128_add(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
{
  xor_bb(out, x, y, 16);
}

/* out = xy.  Arguments may alias. */
void cf_gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
{
  uint8_t Z[16], V[16], zero[16] = { 0 };
 
  /* Z_0 = 0^128
   * V_0 = Y */ 
  memset(Z, 0, 16);
  memcpy(V, y, 16);
  
  for (int i = 0; i < 128; i++)
  {
    uint8_t byte = x[i >> 3];
    uint8_t bit = (byte >> (7 - (i & 7))) & 1;

    select_xor128(Z, zero, V, bit);
    cf_gf128_double_le(V, V);
  }

  memcpy(out, Z, 16);
}
