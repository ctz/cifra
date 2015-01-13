#include "sha2.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "../bignum/handy.h"
#include "cutest.h"
#include "testutil.h"

#undef REALLY_SLOW_TEST

static void vector(const cf_chash *hash, const void *vmsg, size_t nmsg, const char *answer)
{
  uint8_t digest[CF_MAXHASH], expect[CF_MAXHASH];
  const uint8_t *msg = vmsg;
  size_t orig_nmsg = nmsg;

  unhex(expect, sizeof expect, answer);

  cf_chash_ctx ctx;
  hash->init(&ctx);

  /* Input in carefully chosen chunk sizes to exercise blockwise code. */
  if (nmsg)
  {
    hash->update(&ctx, msg, 1);
    nmsg--;
    msg++;
  }

  hash->update(&ctx, msg, nmsg);
  hash->digest(&ctx, digest);
  TEST_CHECK(memcmp(digest, expect, hash->hashsz) == 0);
  
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
  hash->digest(&ctx, digest);
  TEST_CHECK(memcmp(digest, expect, hash->hashsz) == 0);
}

static void hmac_test(const cf_chash *hash,
                      const char *hi_there,
                      const char *jefe,
                      const char *aa_dd,
                      const char *counter_key,
                      const char *long_key,
                      const char *long_message)
{
  uint8_t expect[CF_MAXHASH], sig[CF_MAXHASH];
  uint8_t key[131], message[152];

  /* Key: 0x0b * 20
   * Message: "Hi There"
   */
  unhex(expect, sizeof expect, hi_there);
  memset(key, 0x0b, 20);
  memcpy(message, "Hi There", 8);
  cf_hmac(key, 20, message, 8, sig, hash);
  TEST_CHECK(memcmp(sig, expect, hash->hashsz) == 0);

  /* Key: "Jefe"
   * Message: "what do ya want for nothing?"
   */
  unhex(expect, sizeof expect, jefe);
  memcpy(key, "Jefe", 4);
  memcpy(message, "what do ya want for nothing?", 28);
  cf_hmac(key, 4, message, 28, sig, hash);
  TEST_CHECK(memcmp(sig, expect, hash->hashsz) == 0);

  /* Key: 0xaa * 20
   * Message: 0xdd * 50
   */
  unhex(expect, sizeof expect, aa_dd);
  memset(key, 0xaa, 20);
  memset(message, 0xdd, 50);
  cf_hmac(key, 20, message, 50, sig, hash);
  TEST_CHECK(memcmp(sig, expect, hash->hashsz) == 0);

  /* Key: 0x01..0x19
   * Message: 0xcd * 50
   */
  unhex(expect, sizeof expect, counter_key);
  for (uint8_t i = 1; i < 26; i++)
    key[i - 1] = i;
  memset(message, 0xcd, 50);
  cf_hmac(key, 25, message, 50, sig, hash);
  TEST_CHECK(memcmp(sig, expect, hash->hashsz) == 0);

  /* Key: 0xaa * 131
   * Message: "Test Using Larger Than Block-Size Key - Hash Key First"
   */
  unhex(expect, sizeof expect, long_key);
  memset(key, 0xaa, 131);
  memcpy(message, "Test Using Larger Than Block-Size Key - Hash Key First", 54);
  cf_hmac(key, 131, message, 54, sig, hash);
  TEST_CHECK(memcmp(sig, expect, hash->hashsz) == 0);

  /* Key: 0xaa * 131
   * Message: "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
   */
  unhex(expect, sizeof expect, long_message);
  memset(key, 0xaa, 131);
  memcpy(message, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", 152);
  cf_hmac(key, 131, message, 152, sig, hash);
  TEST_CHECK(memcmp(sig, expect, hash->hashsz) == 0);
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

static void test_hmac_sha224(void)
{
  hmac_test(&cf_sha224,
            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
            "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
            "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
            "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
            "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
            "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1");
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

static void test_hmac_sha256(void)
{
  hmac_test(&cf_sha256,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
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

static void test_hmac_sha384(void)
{
  hmac_test(&cf_sha384,
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e");
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

static void test_hmac_sha512(void)
{
  hmac_test(&cf_sha512,
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");
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

static void check_pkbdf2_sha256(const char *pw, size_t npw,
                                const char *salt, size_t nsalt,
                                uint32_t iters,
                                const char *answer)
{
  uint8_t expect[64];
  size_t nexpect;
  uint8_t output[64];

  nexpect = unhex(expect, sizeof expect, answer);
  cf_pbkdf2_hmac((const void *) pw, npw, 
                 (const void *) salt, nsalt,
                 iters,
                 output, nexpect,
                 &cf_sha256);

  TEST_CHECK(memcmp(expect, output, nexpect) == 0);
}

static void test_pbkdf2_sha256(void)
{
  check_pkbdf2_sha256("password", 8,
                      "salt", 4,
                      1,
                      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

  check_pkbdf2_sha256("password", 8,
                      "salt", 4,
                      2,
                      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");

  check_pkbdf2_sha256("password", 8,
                      "salt", 4,
                      4096,
                      "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");

  check_pkbdf2_sha256("passwordPASSWORDpassword", 24,
                      "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
                      4096,
                      "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");

  check_pkbdf2_sha256("", 0,
                      "salt", 4,
                      1024,
                      "9e83f279c040f2a11aa4a02b24c418f2d3cb39560c9627fa4f47e3bcc2897c3d");

  check_pkbdf2_sha256("password", 8,
                      "", 0,
                      1024,
                      "ea5808411eb0c7e830deab55096cee582761e22a9bc034e3ece925225b07bf46");

  check_pkbdf2_sha256("\x70\x61\x73\x73\x00\x77\x6f\x72\x64", 9,
                      "\x73\x61\x00\x6c\x74", 5,
                      4096,
                      "89b69d0516f829893c696226650a8687");
}

TEST_LIST = {
  { "sha224", test_sha224},
  { "sha256", test_sha256 },
  { "sha384", test_sha384 },
  { "sha512", test_sha512 },

  { "hmac-sha224", test_hmac_sha224 },
  { "hmac-sha256", test_hmac_sha256 },
  { "hmac-sha384", test_hmac_sha384 },
  { "hmac-sha512", test_hmac_sha512 },

  { "pbkdf2-sha256", test_pbkdf2_sha256 },

#ifdef REALLY_SLOW_TEST
  { "sha256-long", test_sha256_long },
#endif
  { 0 }
};

