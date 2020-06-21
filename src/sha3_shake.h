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

/**
 * SHA3 SHAKE functions
 * ===========
 * The functions SHAKE-128 and SHAKE-256. from FIPS 202.
 *
 */

/* SHAKE hashing initialisation function type */
typedef void (*cf_cshake_init)(void *ctx);

/* SHAKE hashing data processing function type */
typedef void (*cf_cshake_update)(void *ctx, const void *data, size_t nbytes);

/* SHAKE hashing completion function type */
typedef void (*cf_cshake_digest)(const void *ctx, uint8_t *hash, size_t noutbytes);

/* .. c:type:: cf_cshake
 * This type describes an incremental SHAKE function in an abstract way.
 *
 * .. c:member:: cf_cshake.blocksz
 * The SHAKE function's internal block size, in bytes.
 *
 * .. c:member:: cf_cshake.init
 * Context initialisation function.
 *
 * .. c:member:: cf_cshake:update
 * Data processing function.
 *
 * .. c:member:: cf_cshake:digest
 * Completion function.
 *
 */
typedef struct
{
  size_t blocksz;
  cf_cshake_init init;
  cf_cshake_update update;
  cf_cshake_digest digest;
} cf_cshake;

/* .. c:function:: $DECL */
extern void cf_shake_128_init(cf_sha3_context *ctx);
/* .. c:function:: $DECL
 * Sets up `ctx` ready to hash a new message.
 */
extern void cf_shake_256_init(cf_sha3_context *ctx);

/* -- update functions -- */

/* .. c:function:: $DECL */
extern void cf_shake_128_update(cf_sha3_context *ctx, const void *data, size_t nbytes);
/* .. c:function:: $DECL
 * Hashes `nbytes` at `data`.  Copies the data for processing later if there
 * isn't enough to make a full block.
 */
extern void cf_shake_256_update(cf_sha3_context *ctx, const void *data, size_t nbytes);

/* -- _digest functions -- */

/* .. c:function:: $DECL */
extern void cf_shake_128_digest(const cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes);
/* .. c:function:: $DECL
 * Finishes the hashing operation, writing result to `hash`.
 *
 * This leaves `ctx` unchanged.
 */
extern void cf_shake_256_digest(const cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes);

/* -- _digest_final functions -- */

/* .. c:function:: $DECL */
extern void cf_shake_128_digest_final(cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes);

/* .. c:function:: $DECL
 * Finishes the hashing operation, writing result to `hash`.
 *
 * This destroys the contents of `ctx`.
 */
extern void cf_shake_256_digest_final(cf_sha3_context *ctx, uint8_t *hash, size_t noutbytes);

/* .. c:function:: $DECL
 * One-shot, general SHAKE computation.
 *
 * :param h: describe which SHAKE algorithm to use.
 * :param m: input message to be hashed.
 * :param nm: length of message.  May be zero.
 * :param out: pointer to output buffer.
 * :param nout: size of output buffer.
 */
extern void cf_shake(const cf_cshake *h, const void *m, size_t nm, uint8_t *out, size_t nout);

/* .. c:var:: cf_shake_128
 * .. c:var:: cf_shake_256
 * Abstract interface to SHAKE functions.  See :c:type:`cf_cshake` for more information.
 */
extern const cf_cshake cf_shake_128;
extern const cf_cshake cf_shake_256;

#endif
