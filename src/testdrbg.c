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

#include "drbg.h"
#include "handy.h"
#include "cutest.h"
#include "testutil.h"

static void test_hashdrbg_sha256_vector(void)
{
  uint8_t entropy[32], nonce[16], persn[32], reseed[32], got[128], expect[128];

  /* This is the first KAT from NIST's CAVP example
   * file for SHA-256 with all inputs used; line 4360. */
  unhex(entropy, sizeof entropy, "b87bb4de5c148d964fc0cb612d69295671780b4270fe32bf389b6f49488efe13");
  unhex(nonce, sizeof nonce, "27eb37a0c695c4ee3c9b70b7f6b33492");
  unhex(persn, sizeof persn, "52321406ac8a9c266b1f8d811bb871269e5824b59a0234f01d358193523bbb7c");
  unhex(reseed, sizeof reseed, "7638267f534c4e6ee22cc6ca6ed824fd5d3d387c00b89dd791eb5ac9766385b8");

  unhex(expect, sizeof expect, "de01c061651bab3cef2fc4ea89a56b6e86e74b2e9fd11ed671c97c813778a06a2c1f41b41e754a5257750c6bde9601da9d67d8d9564f4a8538b92516a2dacc496dee257b85393f2a01ad59aa3257f1b6da9566e3706d2d6d4a26e511b0c64d7dc223acb24827178afa43ca8d5a66f983d6929dc61564c4c14fc32d85765a23f7");

  cf_hash_drbg_sha256 ctx;
  cf_hash_drbg_sha256_init(&ctx, entropy, sizeof entropy, nonce, sizeof nonce, persn, sizeof persn);
  cf_hash_drbg_sha256_reseed(&ctx, reseed, sizeof reseed, NULL, 0);
  cf_hash_drbg_sha256_gen(&ctx, got, sizeof got);
  cf_hash_drbg_sha256_gen(&ctx, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);

  /* This is line 5064 from Hash_DRBG.rsp */
  unhex(entropy, sizeof entropy, "63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569");
  unhex(nonce, sizeof nonce, "808aa38f2a72a62359915a9f8a04ca68");
  /* no persn */
  unhex(reseed, sizeof reseed, "e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3");
  unhex(expect, sizeof expect, "04eec63bb231df2c630a1afbe724949d005a587851e1aa795e477347c8b056621c18bddcdd8d99fc5fc2b92053d8cfacfb0bb8831205fad1ddd6c071318a6018f03b73f5ede4d4d071f9de03fd7aea105d9299b8af99aa075bdb4db9aa28c18d174b56ee2a014d098896ff2282c955a81969e069fa8ce007a180183a07dfae17");

  cf_hash_drbg_sha256_init(&ctx, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  cf_hash_drbg_sha256_reseed(&ctx, reseed, sizeof reseed, NULL, 0);
  cf_hash_drbg_sha256_gen(&ctx, got, sizeof got);
  cf_hash_drbg_sha256_gen(&ctx, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

static void test_hashdrbg_sha256_vector_addnl(void)
{
  uint8_t entropy[32], nonce[16], reseed[32], got[128], expect[128], addnl[32];

  /* Hash_DRBG.rsp, line 5230. No personlisation string, but with additional data. */
  unhex(entropy, sizeof entropy, "9cfb7ad03be487a3b42be06e9ae44f283c2b1458cec801da2ae6532fcb56cc4c");
  unhex(nonce, sizeof nonce, "a20765538e8db31295747ec922c13a69");
  unhex(reseed, sizeof reseed, "96bc8014f90ebdf690db0e171b59cc46c75e2e9b8e1dc699c65c03ceb2f4d7dc");
  unhex(expect, sizeof expect, "71c1154a2a7a3552413970bf698aa02f14f8ea95e861f801f463be27868b1b14b1b4babd9eba5915a6414ab1104c8979b1918f3094925aeab0d07d2037e613b63cbd4f79d9f95c84b47ed9b77230a57515c211f48f4af6f5edb2c308b33905db308cf88f552c8912c49b34e66c026e67b302ca65b187928a1aba9a49edbfe190");

  cf_hash_drbg_sha256 ctx;
  cf_hash_drbg_sha256_init(&ctx, entropy, sizeof entropy, nonce, sizeof nonce, NULL, 0);
  unhex(addnl, sizeof addnl, "6fea0894052dab3c44d503950c7c72bd7b87de87cb81d3bb51c32a62f742286d");
  cf_hash_drbg_sha256_reseed(&ctx, reseed, sizeof reseed, addnl, sizeof addnl);
  unhex(addnl, sizeof addnl, "d3467c78563b74c13db7af36c2a964820f2a9b1b167474906508fdac9b2049a6");
  cf_hash_drbg_sha256_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  unhex(addnl, sizeof addnl, "5840a11cc9ebf77b963854726a826370ffdb2fc2b3d8479e1df5dcfa3dddd10b");
  cf_hash_drbg_sha256_gen_additional(&ctx, addnl, sizeof addnl, got, sizeof got);
  TEST_CHECK(memcmp(got, expect, sizeof got) == 0);
}

TEST_LIST = {
  { "hashdrbg-sha256-1", test_hashdrbg_sha256_vector },
  { "hashdrbg-sha256-2", test_hashdrbg_sha256_vector_addnl },
  { 0 }
};

