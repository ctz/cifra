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

#ifndef TESTSHAKE_H
#define TESTSHAKE_H

#include <stdlib.h>

static void vector_shake(const cf_cshake *hash,
                   const void *vmsg, size_t nmsg,
                   const char *expect, size_t nexpect)
{
  uint8_t *digest;
  const uint8_t *msg = vmsg;
  size_t orig_nmsg = nmsg;
  cf_chash_ctx ctx;

  digest = malloc(nexpect);
  if (digest == NULL) {
    printf("Error malloc() \n");
    return;
  }

  hash->init(&ctx);

  /* Input in carefully chosen chunk sizes to exercise blockwise code. */
  if (nmsg)
  {
    hash->update(&ctx, msg, 1);
    nmsg--;
    msg++;
  }

  hash->update(&ctx, msg, nmsg);
  hash->digest(&ctx, digest, nexpect);
  TEST_CHECK(memcmp(digest, expect, nexpect) == 0);

  /* Now try with other arrangements. */
  msg = vmsg;
  nmsg = orig_nmsg;

  hash->init(&ctx);
  if (nmsg >= hash->blocksz)
  {
    hash->update(&ctx, msg, hash->blocksz - 1);
    nmsg -= hash->blocksz - 1;
    msg += hash->blocksz - 1;
  }

  hash->update(&ctx, msg, nmsg);
  hash->digest(&ctx, digest, nexpect);
  TEST_CHECK(memcmp(digest, expect, nexpect) == 0);

  /* One more arrangement */
  msg = vmsg;
  nmsg = orig_nmsg;

  hash->init(&ctx);
  if (nmsg >= hash->blocksz)
  {
    hash->update(&ctx, msg, hash->blocksz - 1);
    nmsg -= hash->blocksz - 1;
    msg += hash->blocksz - 1;

    hash->update(&ctx, msg, 1);
    nmsg--;
    msg++;
  }

  if (nmsg >= hash->blocksz)
  {
    hash->update(&ctx, msg, hash->blocksz);
    nmsg -= hash->blocksz;
    msg += hash->blocksz;
  }

  hash->update(&ctx, msg, nmsg);
  hash->digest(&ctx, digest, nexpect);
  TEST_CHECK(memcmp(digest, expect, nexpect) == 0);
  free(digest);
}

typedef void (*final_fn)(void *ctx, uint8_t *out, size_t noutbytes);

/* Check incremental interface works, and final function likewise. */
static void vector_shake_abc_final(const cf_cshake *hash, const void *vfinal_fn,
                             const void *expect, size_t nexpect)
{
  uint8_t *digest;
  final_fn final = vfinal_fn;
  cf_chash_ctx ctx;

  digest = malloc(nexpect);
  if (digest == NULL) {
    printf("Error malloc() \n");
    return;
  }

  hash->init(&ctx);
  hash->update(&ctx, "a", 1);
  hash->digest(&ctx, digest, nexpect);
  hash->update(&ctx, "b", 1);
  hash->digest(&ctx, digest, nexpect);
  hash->update(&ctx, "c", 1);
  final(&ctx, digest, nexpect);

  TEST_CHECK(memcmp(expect, digest, nexpect) == 0);
  free(digest);
}

static void test_one_shot_shake(const cf_cshake *hash, const void *vmsg,
                                size_t nmsg, const char *expect, size_t nexpect)
{
  uint8_t *digest;

  digest = malloc(nexpect);
  if (digest == NULL) {
    printf("Error malloc() \n");
    return;
  }

  cf_shake(hash, vmsg, nmsg, digest, nexpect);
  TEST_CHECK(memcmp(digest, expect, nexpect) == 0);
}

#endif
