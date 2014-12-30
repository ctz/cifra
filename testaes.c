#include "aes.h"
#include "modes.h"
#include "bitops.h"

#include "handy.h"
#include "ext/cutest.h"
#include "testutil.h"

static void test_bitopts(void)
{
  uint8_t tab8[8];
  uint32_t tab32[32];
  
  for (size_t i = 0; i < 8; i++)
    tab8[i] = 1 << i;
  for (size_t i = 0; i < 32; i++)
    tab32[i] = 1 << i;

  for (size_t i = 0; i < 8; i++)
  {
    TEST_CHECK(select_u8(i, tab8, 8) == tab8[i]);
  }

  for (size_t i = 0; i < 32; i++)
  {
    TEST_CHECK(select_u32(i, tab32, 32) == tab32[i]);
  }
}

static void test_expand(const uint8_t *key, size_t nkey,
                        const uint32_t *answer, size_t roundkeys)
{
  cf_aes_context ctx;

  cf_aes_init(&ctx, key, nkey);

  for (size_t i = 0; i < roundkeys; i++)
  {
    TEST_CHECK(ctx.ks[i] == answer[i]);
  }
}

static void test_expand_128(void)
{
  /* This is FIPS-197 appendix A.1. */
  const uint8_t key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  };

  const uint32_t answer[] = {
    0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1,
    0x23a33939, 0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
    0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f,
    0xb671253b, 0xdb0bad00, 0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
    0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd, 0x4e54f70e, 0x5f5fc9f3,
    0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
    0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
    0xe13f0cc8, 0xb6630ca6
  };
  
  test_expand(key, sizeof key, answer, ARRAYCOUNT(answer));
}

static void test_expand_192(void)
{
  /* This is FIPS-197 appendix A.2. */
  const uint8_t key[] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 
    0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
  };

  const uint32_t answer[] = {
    0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b,
    0xfe0c91f7, 0x2402f5a5, 0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2,
    0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd, 0xe75fad44, 0xbb095386,
    0x485af057, 0x21efb14f, 0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6,
    0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767, 0xc0a69407, 0xd19da4e1,
    0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3,
    0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 0xa7e1466c, 0x9411f1df,
    0x821f750a, 0xad07d753, 0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5,
    0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202
  };

  test_expand(key, sizeof key, answer, ARRAYCOUNT(answer));
}

static void test_expand_256(void)
{
  /* And this is A.3. */
  const uint8_t key[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
    0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
  };

  const uint32_t answer[] = {
    0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7,
    0x2d9810a3, 0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde,
    0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917,
    0xfee94248, 0xde8ebe96, 0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
    0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464, 0x98c5bfc9, 0xbebd198e,
    0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80,
    0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71,
    0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
    0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34,
    0x9adf6ace, 0xbd10190d, 0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e
  };

  test_expand(key, sizeof key, answer, ARRAYCOUNT(answer));
}

static void test_cipher_example(void)
{
  const uint8_t key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
  };

  const uint8_t input[] = {
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2,
    0xe0, 0x37, 0x07, 0x34
  };

  const uint8_t expected[] = {
    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97,
    0x19, 0x6a, 0x0b, 0x32
  };

  uint8_t output[AES_BLOCKSZ];

  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);
  cf_aes_encrypt(&ctx, input, output);
  cf_aes_finish(&ctx);

  TEST_CHECK(memcmp(expected, output, sizeof expected) == 0);
}

static void vector(const char *input, const char *output,
                   const char *key)
{
  uint8_t keybuf[32], inbuf[16], outbuf[16], tmp[16];
  size_t nkey = sizeof keybuf;
  cf_aes_context ctx;

  nkey = unhex(keybuf, 32, key);
  unhex(inbuf, 16, input);
  unhex(outbuf, 16, output);

  cf_aes_init(&ctx, keybuf, nkey);
  cf_aes_encrypt(&ctx, inbuf, tmp);
  TEST_CHECK(memcmp(tmp, outbuf, 16) == 0);
  
  cf_aes_decrypt(&ctx, outbuf, tmp);
  TEST_CHECK(memcmp(tmp, inbuf, 16) == 0);
  cf_aes_finish(&ctx);
}

static void test_vectors(void)
{
  vector("00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a",
         "000102030405060708090a0b0c0d0e0f");
  vector("00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191",
         "000102030405060708090a0b0c0d0e0f1011121314151617");
  vector("00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

static void test_cbc(void)
{
  uint8_t iv[16], key[16], inp[16], out[16], expect[16];

  unhex(iv, 16, "000102030405060708090A0B0C0D0E0F");
  unhex(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
  unhex(inp, 16, "6bc1bee22e409f96e93d7e117393172a");
  unhex(expect, 16, "7649abac8119b246cee98e9b12e9197d");

  cf_aes_context aes;
  cf_aes_init(&aes, key, sizeof key);

  cf_cbc cbc;
  cf_cbc_init(&cbc, &cf_aes, &aes, iv);
  cf_cbc_encrypt(&cbc, inp, out, 1);
  TEST_CHECK(memcmp(out, expect, 16) == 0);

  cf_cbc_init(&cbc, &cf_aes, &aes, iv);
  cf_cbc_decrypt(&cbc, out, expect, 1);
  TEST_CHECK(memcmp(expect, inp, 16) == 0);
}

static void test_ctr(void)
{
  uint8_t nonce[16], key[16], inp[16], out[16], expect[16];

  unhex(nonce, 16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  unhex(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
  unhex(inp, 16, "6bc1bee22e409f96e93d7e117393172a");
  unhex(expect, 16, "874d6191b620e3261bef6864990db6ce");

  cf_aes_context aes;
  cf_aes_init(&aes, key, sizeof key);

  cf_ctr ctr;
  cf_ctr_init(&ctr, &cf_aes, &aes, nonce);
  cf_ctr_cipher(&ctr, inp, out, 16);
  TEST_CHECK(memcmp(expect, out, 16) == 0);

  cf_ctr_init(&ctr, &cf_aes, &aes, nonce);
  cf_ctr_cipher(&ctr, out, expect, 16);
  TEST_CHECK(memcmp(expect, inp, 16) == 0);

  memset(nonce, 0xff, 16);
  memset(inp, 0x00, 16);
  cf_ctr_init(&ctr, &cf_aes, &aes, nonce);

  /* Exercise cf_blockwise_xor code paths. */
  for (int i = 0; i < 1024; i++)
  {
    cf_ctr_cipher(&ctr, inp, out, i % 16);
  }

  /* expected counter value is 1024 * 7.5 / 16 - 1:
   * 479 = 0x1df
   */

  memset(nonce, 0, 16);
  nonce[15] = 0xdf;
  nonce[14] = 0x01;

  TEST_CHECK(memcmp(nonce, ctr.nonce, 16) == 0);
}

static void test_eax(void)
{
  uint8_t key[16], nonce[16], header[8], msg[2], cipher[2], tag[16];

  /*
   * MSG: F7FB
   * KEY: 91945D3F4DCBEE0BF45EF52255F095A4
   * NONCE: BECAF043B0A23D843194BA972C66DEBD
   * HEADER: FA3BFD4806EB53FA
   * CIPHER: 19DD5C4C9331049D0BDAB0277408F67967E5
   */

  unhex(key, 16, "91945D3F4DCBEE0BF45EF52255F095A4");
  unhex(nonce, 16, "BECAF043B0A23D843194BA972C66DEBD");
  unhex(header, 8, "FA3BFD4806EB53FA");
  unhex(msg, 2, "F7FB");

  cf_aes_context aes;
  cf_aes_init(&aes, key, sizeof key);

  cf_eax_encrypt(&cf_aes, &aes,
                 msg, sizeof msg,
                 header, sizeof header,
                 nonce, sizeof nonce,
                 cipher,
                 tag, sizeof tag);

  TEST_CHECK(memcmp("\x19\xdd", cipher, 2) == 0);
  TEST_CHECK(memcmp("\x5c\x4c\x93\x31\x04\x9d\x0b\xda\xb0\x27\x74\x08\xf6\x79\x67\xe5", tag, sizeof tag) == 0);

  int rc;
  uint8_t tmp[2];
  rc = cf_eax_decrypt(&cf_aes, &aes,
                      cipher, sizeof cipher,
                      header, sizeof header,
                      nonce, sizeof nonce,
                      tag, sizeof tag,
                      tmp);
  TEST_CHECK(rc == 0);
  TEST_CHECK(memcmp(tmp, msg, sizeof msg) == 0);
}

static void check_cmac(const char *keystr, size_t nkey,
                       const char *msgstr, size_t nmsg,
                       const char *tagstr)
{
  uint8_t key[32], msg[256], gottag[16], wanttag[16];

  unhex(key, nkey, keystr);
  unhex(msg, nmsg, msgstr);
  unhex(wanttag, 16, tagstr);

  cf_aes_context aes;
  cf_aes_init(&aes, key, nkey);

  cf_cmac cmac;
  cf_cmac_init(&cmac, &cf_aes, &aes);
  cf_cmac_sign(&cmac, msg, nmsg, gottag);

  TEST_CHECK(memcmp(gottag, wanttag, cf_aes.blocksz) == 0);
}

static void test_cmac(void)
{
  /* These from SP800-38B */
  check_cmac("2b7e151628aed2a6abf7158809cf4f3c", 16,
             "", 0,
             "bb1d6929e95937287fa37d129b756746");
  check_cmac("2b7e151628aed2a6abf7158809cf4f3c", 16,
             "6bc1bee22e409f96e93d7e117393172a", 16,
             "070a16b46b4d4144f79bdd9dd04a287c");
  check_cmac("2b7e151628aed2a6abf7158809cf4f3c", 16,
             "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", 40,
             "dfa66747de9ae63030ca32611497c827");
  check_cmac("2b7e151628aed2a6abf7158809cf4f3c", 16,
             "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64,
             "51f0bebf7e3b9d92fc49741779363cfe");

  check_cmac("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 24,
             "", 0,
             "d17ddf46adaacde531cac483de7a9367");
  check_cmac("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 24,
             "6bc1bee22e409f96e93d7e117393172a", 16,
             "9e99a7bf31e710900662f65e617c5184");
  check_cmac("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 24,
             "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", 40,
             "8a1de5be2eb31aad089a82e6ee908b0e");
  check_cmac("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 24,
             "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64,
             "a1d5df0eed790f794d77589659f39a11");

  check_cmac("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 32,
             "", 0,
             "028962f61b7bf89efc6b551f4667d983");
  check_cmac("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 32,
             "6bc1bee22e409f96e93d7e117393172a", 16,
             "28a7023f452e8f82bd4bf28d8c37c35c");
  check_cmac("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 32,
             "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", 40,
             "aaf3d8f1de5640c232f5b169b9c911e6");
  check_cmac("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 32,
             "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64,
             "e1992190549f6ed5696a2c056c315410");
}

TEST_LIST = {
  { "bitops", test_bitopts },
  { "key-expansion-128", test_expand_128 },
  { "key-expansion-192", test_expand_192 },
  { "key-expansion-256", test_expand_256 },
  { "cipher-example", test_cipher_example },
  { "vectors", test_vectors },
  { "cbc", test_cbc },
  { "ctr", test_ctr },
  { "eax", test_eax },
  { "cmac", test_cmac },
  { 0 }
};

