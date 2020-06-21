/*
 * cifra - embedded cryptography library
 * Written in 2020 by Silex Insight.
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

#ifndef SHA3_SHAKE_H
#define SHA3_SHAKE_H

#include "chash.h"
#include "sha3.h"

/* SHAKE hashing initialisation function type */
typedef void (*cf_cshake_init)(void *ctx);

/* SHAKE hashing data processing function type */
typedef void (*cf_cshake_update)(void *ctx, const void *data, size_t nbytes);

/* SHAKE hashing completion function type */
typedef void (*cf_cshake_digest)(const void *ctx, uint8_t *hash, size_t noutbytes);

/* This type describes an incremental SHAKE function in an abstract way */
typedef struct
{
  size_t blocksz;
  cf_cshake_init init;
  cf_cshake_update update;
  cf_cshake_digest digest;
} cf_cshake;

/* init functions */
extern void cf_shake_128_init(cf_sha3_context *ctx);
extern void cf_shake_256_init(cf_sha3_context *ctx);

/* update functions */
extern void cf_shake_128_update(cf_sha3_context *ctx, const void *data, size_t nbytes);
extern void cf_shake_256_update(cf_sha3_context *ctx, const void *data, size_t nbytes);

/* digest functions (leave `ctx` unchanged) */
extern void cf_shake_128_digest(const cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes);
extern void cf_shake_256_digest(const cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes);

/* digest final functions (destroy the contents of `ctx`) */
extern void cf_shake_128_digest_final(cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes);
extern void cf_shake_256_digest_final(cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes);

/* one shot function */
extern void cf_shake(const cf_cshake *h, const void *m, size_t nm, uint8_t *out, size_t nout);

/* abstract interfaces to SHA3 functions */
extern const cf_cshake cf_shake_128;
extern const cf_cshake cf_shake_256;

#endif
