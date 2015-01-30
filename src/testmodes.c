#include "aes.h"
#include "modes.h"
#include "bitops.h"
#include "gf128.h"

#include "handy.h"
#include "cutest.h"
#include "testutil.h"

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

static void cbcmac_vector(const char *tagstr, const char *keystr, const char *msgstr)
{
  uint8_t message[40], key[32], tag[16], tag_expect[16];

  size_t nmessage = unhex(message, sizeof message, msgstr);
  size_t nkey = unhex(key, sizeof key, keystr);
  unhex(tag_expect, sizeof tag_expect, tagstr);

  cf_aes_context aes;
  cf_aes_init(&aes, key, nkey);

  cf_cbcmac_stream cm;
  cf_cbcmac_stream_init(&cm, &cf_aes, &aes);
  cf_cbcmac_stream_update(&cm, message, nmessage);
  cf_cbcmac_stream_pad_final(&cm, tag);

  TEST_CHECK(memcmp(tag, tag_expect, sizeof tag) == 0);
}

static void test_cbcmac(void)
{
  cbcmac_vector("f0f18975a0859d13a49d3dbfc6cd65d9", "04f7f778621d1e2c8647822a50d98a83", "831be74b9be685c838e22a25a311cb14796235f52898d0");
  cbcmac_vector("0d6a138f75b75694d515c5555eeedd92", "ff845afc51f20635a48f6cec9f781f2e", "c5853e6b3f7ef510936e30d554135f0d5543928c53fc2f81a3");
  cbcmac_vector("96813db17eac06b97942a73a7c5a0aad", "10771647232eda4023d7c5c9bb512e93", "06535f70d96c8050856b024f67ae87dec8d29dabb71f559351000a3c8ffc6360");
  cbcmac_vector("20dda5b1c11400909741ef3bc6ace8ec", "5b39db4ba4531f97f9ca4bdded9b2853", "4991b33540da4d8adfe9374bb4e1c5");
  cbcmac_vector("c02f8f0aba134b6b1669fb582fc1c876", "d022c7e785d2fca4d67faa18b1a9fd9d7a47370933430632", "2ba28ea562dd9c5e80ccaf801677");
  cbcmac_vector("05794b5fc8f2ee8774cd889f7c29eba0", "e451db268e2a26d1bf783eab5dc6f93fb2c5e25ce861283c", "ea14faaa954812cb");
  cbcmac_vector("6a144baa39f619716265d34e53b4c67c", "ff46380f62a9377fb2418844392a97f5b99ac037f9c6753f", "6404534ca80a60f65e22b6c4d7f3a933f93e");
  cbcmac_vector("f71d165cbaac0ff01a1275f85b6a8e15", "67ce476c110ea1bcf081302b5fe23bbc34c54d4601ed4904", "94b125634949467e7aa00ea11025219ac91f0deda110307e0884ee09e8315381");
  cbcmac_vector("22fb7e4c77127ced2caaf98d9f351560", "1c50c0797cd67f8926d1c9b985f9eeaf183f070b3ad25f7efa0895fe98e34391", "7d1e7e199ad4f43fcfff55f7c981e613c022ab7f83922172657978cdf08b36");
  cbcmac_vector("40c1eff3f4715458773cd30796dffd54", "3c1eaea74af6ee439bd7a37638d6082160e61b232bf8a45d05d5f489043e2d19", "d2a3381a82d6b6c25293431ddc1d73b5148240fe00c324528d69c6114e4ca940cdfb2917");
  cbcmac_vector("697c6595a21fa2fa3ad360687aed6837", "c2da01b412a5cd1c75b5085fd2ee79c347d9f912863d81d04289759658704705", "65229b7715e502540490fbe2bf5a8eb0bf64ff7fb7ab7f18697b");
  cbcmac_vector("f52d651684430de81f295106ecf0a5d2", "76ffb3385bca7c93c012d7bcb3a3d0f287a70a913676a78d2847058e75ae5e3c", "129091653237d035f64042a74f61a99c8fd6849a860e57e7e4");
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
  cf_ctr_cipher(&ctr, inp, out, 16); /* one piece */
  TEST_CHECK(memcmp(expect, out, 16) == 0);
  
  cf_ctr_init(&ctr, &cf_aes, &aes, nonce);
  cf_ctr_cipher(&ctr, inp, out, 1); /* incremental (2 blocks) */
  cf_ctr_cipher(&ctr, inp, out, 16);
  cf_ctr_cipher(&ctr, inp, out, 16);
  
  cf_ctr_init(&ctr, &cf_aes, &aes, nonce);
  cf_ctr_cipher(&ctr, inp, out, 1); /* incremental */
  cf_ctr_cipher(&ctr, inp + 1, out + 1, 15);
  TEST_CHECK(memcmp(expect, out, 16) == 0);

  cf_ctr_init(&ctr, &cf_aes, &aes, nonce);
  cf_ctr_cipher(&ctr, out, expect, 16); /* decrypt */
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

  tag[0] ^= 0xff;
  rc = cf_eax_decrypt(&cf_aes, &aes,
                      cipher, sizeof cipher,
                      header, sizeof header,
                      nonce, sizeof nonce,
                      tag, sizeof tag,
                      tmp);
  TEST_CHECK(rc == 1);
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

static void test_gf128_mul(void)
{
  uint8_t bx[16], by[16], bout[16], bexpect[16];

  unhex(bx, sizeof bx, "0388dace60b6a392f328c2b971b2fe78");
  unhex(by, sizeof by, "66e94bd4ef8a2c3b884cfa59ca342b2e");
  unhex(bexpect, sizeof bexpect, "5e2ec746917062882c85b0685353deb7");

  cf_gf128 x, y, out;
  cf_gf128_frombytes_be(bx, x);
  cf_gf128_frombytes_be(by, y);
  cf_gf128_mul(x, y, out);
  cf_gf128_tobytes_be(out, bout);
  TEST_CHECK(memcmp(bexpect, bout, 16) == 0);
}

static void check_gcm(const char *keystr,
                      const char *plainstr,
                      const char *aadstr,
                      const char *ivstr,
                      const char *cipherstr,
                      const char *tagstr)
{
  uint8_t key[32],
          plain[64],
          plain_decrypt[64],
          aad[64],
          iv[64],
          cipher_expect[64],
          cipher[64],
          tag_expect[16],
          tag[16];

  size_t nkey = unhex(key, sizeof key, keystr),
         nplain = unhex(plain, sizeof plain, plainstr),
         naad = unhex(aad, sizeof aad, aadstr),
         niv = unhex(iv, sizeof iv, ivstr),
         ncipher = unhex(cipher_expect, sizeof cipher_expect, cipherstr),
         ntag = unhex(tag_expect, sizeof tag_expect, tagstr);

  assert(ncipher == nplain);

  cf_aes_context ctx;
  cf_aes_init(&ctx, key, nkey);

  cf_gcm_encrypt(&cf_aes, &ctx,
                 plain, nplain,
                 aad, naad,
                 iv, niv,
                 cipher,
                 tag, ntag);

  TEST_CHECK(memcmp(tag, tag_expect, ntag) == 0);
  TEST_CHECK(memcmp(cipher, cipher_expect, ncipher) == 0);

  int err = cf_gcm_decrypt(&cf_aes, &ctx,
                           cipher, ncipher,
                           aad, naad,
                           iv, niv,
                           tag, ntag,
                           plain_decrypt);
  TEST_CHECK(err == 0);
  TEST_CHECK(memcmp(plain_decrypt, plain, ncipher) == 0);

  tag[0] ^= 0xff;
  err = cf_gcm_decrypt(&cf_aes, &ctx,
                       cipher, ncipher,
                       aad, naad,
                       iv, niv,
                       tag, ntag,
                       plain_decrypt);
  TEST_CHECK(err == 1);
}

static void test_gcm(void)
{
  check_gcm("00000000000000000000000000000000",
            "",
            "",
            "000000000000000000000000",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a");
  check_gcm("00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf");
  check_gcm("feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255",
            "",
            "cafebabefacedbaddecaf888",
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4");
  check_gcm("feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            "abaddad2",
            "cafebabefacedbaddecaf888",
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47");
  check_gcm("feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            "abaddad2",
            "cafebabefacedbad",
            "61353b4c2806934a777ff51fa22a4755"
            "699b2a714fcdc6f83766e5f97b6c7423"
            "73806900e49f24b22b097544d4896b42"
            "4989b5e1ebac0f07c23f4598",
            "3612d2e79e3b0785561be14aaca2fccb");
  check_gcm("feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            "abaddad2",
            "9313225df88406e555909c5aff5269aa"
            "6a7a9538534f7da1e4c303d2a318a728"
            "c3c0c95156809539fcf0e2429a6b5254"
            "16aedbf5a0de6a57a637b39b",
            "8ce24998625615b603a033aca13fb894"
            "be9112a5c3a211a8ba262a3cca7e2ca7"
            "01e4a9a4fba43c90ccdcb281d48c7c6f"
            "d62875d2aca417034c34aee5",
            "619cc5aefffe0bfa462af43c1699d050");

  check_gcm("feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            "abaddad2",
            "9313225df88406e555909c5aff5269aa"
            "6a7a9538534f7da1e4c303d2a318a728"
            "c3c0c95156809539fcf0e2429a6b5254"
            "16aedbf5a0de6a57a637b39b",
            "8ce24998625615b603a033aca13fb894"
            "be9112a5c3a211a8ba262a3cca7e2ca7"
            "01e4a9a4fba43c90ccdcb281d48c7c6f"
            "d62875d2aca417034c34aee5",
            "619cc5aefffe0bfa462af43c1699d050");
  check_gcm("000000000000000000000000000000000000000000000000",
            "",
            "",
            "000000000000000000000000",
            "",
            "cd33b28ac773f74ba00ed1f312572435");
  check_gcm("000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "000000000000000000000000",
            "98e7247c07f0fe411c267e4384b0f600",
            "2ff58d80033927ab8ef4d4587514f0fb");
  check_gcm("feffe9928665731c6d6a8f9467308308"
            "feffe9928665731c",
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255",
            "",
            "cafebabefacedbaddecaf888",
            "3980ca0b3c00e841eb06fac4872a2757"
            "859e1ceaa6efd984628593b40ca1e19c"
            "7d773d00c144c525ac619d18c84a3f47"
            "18e2448b2fe324d9ccda2710acade256",
            "9924a7c8587336bfb118024db8674a14");
}

static void check_ccm(const char *keystr,
                      const char *headerstr,
                      const char *plainstr,
                      const char *noncestr,
                      const char *cipherstr,
                      const char *tagstr)
{
  uint8_t key[32], header[32], plain[32], nonce[32], cipher[32], tag[16];
  uint8_t expectcipher[32], expecttag[16], decrypted[32];

  size_t nkey = unhex(key, sizeof key, keystr);
  size_t nheader = unhex(header, sizeof header, headerstr);
  size_t nplain = unhex(plain, sizeof plain, plainstr);
  size_t nnonce = unhex(nonce, sizeof nonce, noncestr);
  size_t ncipher = unhex(expectcipher, sizeof expectcipher, cipherstr);
  size_t ntag = unhex(expecttag, sizeof expecttag, tagstr);

  assert(ncipher == nplain);

  cf_aes_context ctx;
  cf_aes_init(&ctx, key, nkey);

  cf_ccm_encrypt(&cf_aes, &ctx,
                 plain, nplain, 15 - nnonce,
                 header, nheader,
                 nonce, nnonce,
                 tag, ntag,
                 cipher);

  TEST_CHECK(memcmp(tag, expecttag, ntag) == 0);
  TEST_CHECK(memcmp(cipher, expectcipher, ncipher) == 0);

  int err;
  err = cf_ccm_decrypt(&cf_aes, &ctx,
                       expectcipher, ncipher, 15 - nnonce,
                       header, nheader,
                       nonce, nnonce,
                       tag, ntag,
                       decrypted);
  TEST_CHECK(err == 0);
  TEST_CHECK(memcmp(decrypted, plain, nplain) == 0);

  tag[0] ^= 0xff;
  
  err = cf_ccm_decrypt(&cf_aes, &ctx,
                       expectcipher, ncipher, 15 - nnonce,
                       header, nheader,
                       nonce, nnonce,
                       tag, ntag,
                       decrypted);
  TEST_CHECK(err == 1);
}

static void fill(uint8_t *buf, size_t len, uint8_t b)
{
  for (size_t i = 0; i < len; i++)
    buf[i] = b++;
}

static void check_ccm_long(void)
{
  /* This is example 4 from SP800-38C, to test the long AAD code path. */
  uint8_t header[0x10000];
  uint8_t key[16];
  uint8_t tag[14], expect_tag[14];
  uint8_t nonce[13];
  uint8_t plain[32], cipher[32], expect_cipher[32];

  fill(header, sizeof header, 0x00);
  fill(key, sizeof key, 0x40);
  fill(nonce, sizeof nonce, 0x10);
  fill(plain, sizeof plain, 0x20);

  unhex(expect_tag, sizeof expect_tag,
        "b4ac6bec93e8598e7f0dadbcea5b");
  unhex(expect_cipher, sizeof expect_cipher,
        "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72");

  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);

  cf_ccm_encrypt(&cf_aes, &ctx,
                 plain, sizeof plain, 15 - sizeof nonce,
                 header, sizeof header,
                 nonce, sizeof nonce,
                 tag, sizeof tag,
                 cipher);

  TEST_CHECK(memcmp(expect_tag, tag, sizeof tag) == 0);
  TEST_CHECK(memcmp(expect_cipher, cipher, sizeof cipher) == 0);
}

static void test_ccm(void)
{
  check_ccm("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
            "0001020304050607",
            "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            "00000003020100a0a1a2a3a4a5",
            "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384",
            "17E8D12CFDF926E0");

  check_ccm("404142434445464748494a4b4c4d4e4f",
            "0001020304050607",
            "20212223",
            "10111213141516",
            "7162015b",
            "4dac255d");

  check_ccm("404142434445464748494a4b4c4d4e4f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "202122232425262728292a2b2c2d2e2f3031323334353637",
            "101112131415161718191a1b",
            "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5",
            "484392fbc1b09951");

  check_ccm_long();
}

TEST_LIST = {
  { "cbc", test_cbc },
  { "cbcmac", test_cbcmac },
  { "ctr", test_ctr },
  { "eax", test_eax },
  { "cmac", test_cmac },
  { "gf128-mul", test_gf128_mul },
  { "gcm", test_gcm },
  { "ccm", test_ccm },
  { 0 }
};

