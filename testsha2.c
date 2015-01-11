#include "sha2.h"
#include "../bignum/handy.h"
#include "cutest.h"
#include "testutil.h"

#undef REALLY_SLOW_TEST

static void vector(const cf_chash *hash, const void *msg, size_t nmsg, const char *answer)
{
  uint8_t digest[CF_MAXHASH], expect[CF_MAXHASH];

  unhex(expect, sizeof expect, answer);

  cf_hash(hash, msg, nmsg, digest); 
  TEST_CHECK(memcmp(digest, expect, hash->hashsz) == 0);
}

typedef void (*final_fn)(void *ctx, uint8_t *out);

static void vector_abc_final(const cf_chash *hash, const void *vfinal_fn, const char *answer)
{
  uint8_t expect[CF_MAXHASH], digest[CF_MAXHASH];

  unhex(expect, sizeof expect, answer);

  final_fn final = vfinal_fn;
  cf_chash_ctx ctx;
  hash->init(&ctx);
  hash->update(&ctx, "a", 1);
  hash->digest(&ctx, digest);
  hash->update(&ctx, "b", 1);
  hash->digest(&ctx, digest);
  hash->update(&ctx, "c", 1);
  final(&ctx, digest);

  TEST_CHECK(memcmp(expect, digest, hash->hashsz) == 0);
}

static void test_sha224(void)
{
  const cf_chash *h = &cf_sha224;
  vector(h, "", 0, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
  vector(h, "abc", 3, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
  vector(h, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
         "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
  vector(h, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
         "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3");
  
  /* Check that incremental interface produces correct results. */
  vector_abc_final(h, cf_sha224_digest_final, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
}

static void test_sha256(void)
{
  const cf_chash *h = &cf_sha256;
  vector(h, "", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  vector(h, "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  vector(h, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  vector(h, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

  vector_abc_final(h, cf_sha256_digest_final, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_sha384(void)
{
  const cf_chash *h = &cf_sha384;
  vector(h, "", 0, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
  vector(h, "abc", 3, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
  vector(h, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
         "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
  vector(h, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
         "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");

  vector_abc_final(h, cf_sha384_digest_final, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
}

static void test_sha512(void)
{
  const cf_chash *h = &cf_sha512;
  vector(h, "", 0, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
  vector(h, "abc", 3, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  vector(h, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
         "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
  vector(h, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
         "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

  vector_abc_final(h, cf_sha512_digest_final, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

#ifdef REALLY_SLOW_TEST
static void test_sha256_long(void)
{
  uint8_t digest[32];
  cf_sha256_context ctx;
  cf_sha256_init(&ctx);

  for (size_t i = 0; i < 0x1000000; i++)
    cf_sha256_update(&ctx, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 64);
  cf_sha256_digest_final(&ctx, digest);

  uint8_t expect[32];
  unhex(expect, sizeof expect, "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e");
  TEST_CHECK(memcmp(expect, digest, sizeof digest) == 0);
}
#endif

TEST_LIST = {
  { "sha224", test_sha224},
  { "sha256", test_sha256 },
  { "sha384", test_sha384 },
  { "sha512", test_sha512 },

#ifdef REALLY_SLOW_TEST
  { "sha256-long", test_sha256_long },
#endif
  { 0 }
};

