#ifndef BITOPS_H
#define BITOPS_H

#include <stdint.h>
#include <stddef.h>

/* Assorted bitwise and common operations used in ciphers. */

/** Circularly rotate right x by n bits.
 *  0 > n > 32. */
static inline uint32_t rotr32(uint32_t x, unsigned n)
{
  return (x >> n) | (x << (32 - n));
}

/** Circularly rotate left x by n bits.
 *  0 > n > 32. */
static inline uint32_t rotl32(uint32_t x, unsigned n)
{
  return (x << n) | (x >> (32 - n));
}

/** Circularly rotate right x by n bits.
 *  0 > n > 64. */
static inline uint64_t rotr64(uint64_t x, unsigned n)
{
  return (x >> n) | (x << (64 - n));
}

/** Circularly rotate left x by n bits.
 *  0 > n > 64. */
static inline uint64_t rotl64(uint64_t x, unsigned n)
{
  return (x << n) | (x >> (64 - n));
}

/** Read 4 bytes from buf, as a 32-bit big endian quantity. */
static inline uint32_t read32_be(const uint8_t buf[4])
{
  return (buf[0] << 24) |
         (buf[1] << 16) |
         (buf[2] << 8) |
         (buf[3]);
}

/** Read 8 bytes from buf, as a 64-bit big endian quantity. */
static inline uint64_t read64_be(const uint8_t buf[8])
{
  return ((uint64_t)buf[0] << 56) |
         ((uint64_t)buf[1] << 48) |
         ((uint64_t)buf[2] << 40) |
         ((uint64_t)buf[3] << 32) |
         ((uint64_t)buf[4] << 24) |
         ((uint64_t)buf[5] << 16) |
         ((uint64_t)buf[6] << 8) |
         ((uint64_t)buf[7]);
}

/** Encode v as a 32-bit big endian quantity into buf. */
static inline void write32_be(uint32_t v, uint8_t buf[4])
{
  *buf++ = (v >> 24) & 0xff;
  *buf++ = (v >> 16) & 0xff;
  *buf++ = (v >> 8) & 0xff;
  *buf   = v & 0xff;
}

/** Encode v as a 64-bit big endian quantity into buf. */
static inline void write64_be(uint64_t v, uint8_t buf[8])
{
  *buf++ = (v >> 56) & 0xff;
  *buf++ = (v >> 48) & 0xff;
  *buf++ = (v >> 40) & 0xff;
  *buf++ = (v >> 32) & 0xff;
  *buf++ = (v >> 24) & 0xff;
  *buf++ = (v >> 16) & 0xff;
  *buf++ = (v >> 8) & 0xff;
  *buf   = v & 0xff;
}

/** out = in ^ b8.
 *  out and in may alias. */
static inline void xor_b8(uint8_t *out, const uint8_t *in, uint8_t b8, size_t len)
{
  for (size_t i = 0; i < len; i++)
    out[i] = in[i] ^ b8;
}

/** out = x ^ y.
 *  out, x and y may alias. */
static inline void xor_bb(uint8_t *out, const uint8_t *x, const uint8_t *y, size_t len)
{
  for (size_t i = 0; i < len; i++)
    out[i] = x[i] ^ y[i];
}

/** Produce 0xffffffff if x == y, zero otherwise, without branching. */
static inline uint32_t mask_u32(uint32_t x, uint32_t y)
{
  return - (uint32_t) (x == y);
}

/** Select the ith entry from the given table of n values, in a side channel-silent
 *  way. */
static inline uint32_t select_u32(uint32_t i, volatile const uint32_t *tab, uint32_t n)
{
  uint32_t r = 0;

  for (uint32_t ii = 0; ii < n; ii++)
  {
    uint32_t mask = mask_u32(i, ii);
    r = (r & ~mask) | (tab[ii] & mask);
  }

  return r;
}

/** Select the ith entry from the given table of n values, in a side channel-silent
 *  way. */
static inline uint8_t select_u8(uint32_t i, volatile const uint8_t *tab, uint32_t n)
{
  uint8_t r = 0;

  for (uint32_t ii = 0; ii < n; ii++)
  {
    uint8_t mask = mask_u32(i, ii) & 0xff;
    r = (r & ~mask) | (tab[ii] & mask);
  }

  return r;
}

#endif
