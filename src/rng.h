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

#ifndef RNG_H
#define RNG_H

#include <stddef.h>
#include <stdint.h>

/**
 * General random generation interface
 * ===================================
 * This allows us to do random number generation without depending
 * on a specific algorithm.
 */

typedef struct cf_rng cf_rng;

/* .. c:type:: cf_rng_genbytes
 * General random number generation function.
 *
 * Functions of this type write `count` bytes of random data to `data`.
 * Functions cannot fail except fatally.
 *
 * :rtype: void
 * :param ctx: rng-specific context structure.
 * :param data: output buffer.
 * :param count: number of bytes to generate.
 */
typedef void (*cf_rng_genbytes)(void *ctx, void *data, size_t count);

/* .. c:type:: cf_rng
 * This type describes a random number generator in an abstract way.
 *
 * .. c:member:: cf_rng.getbytes
 * Random generation function.
 *
 */
struct cf_rng
{
  cf_rng_genbytes generate;
};

#endif
