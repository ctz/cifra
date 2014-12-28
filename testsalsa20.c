
#include "salsa20.h"
#include "testutil.h"
#include "handy.h"
#include "ext/cutest.h"

static void test_salsa20_core(void)
{
  uint8_t k0[16], k1[16], nonce[16], sigma[16], out[64], expect[64];

  /* From section 8. */
  memset(k0, 0, sizeof k0);
  memset(k1, 0, sizeof k1);
  memset(nonce, 0, sizeof nonce);
  memset(sigma, 0, sizeof sigma);

  cf_salsa20_core(k0, k1, nonce, sigma, out);
  
  unhex(expect, 64, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
  TEST_CHECK(memcmp(expect, out, 64) == 0);

  /*
  d39f0d73
  4c3752b70375de25bfbbea8831edb330
  016ab2db
  afc7a6305610b3cf1ff0203f0f535da1
  74933071
  ee37cc244fc9eb4f03519c2fcb1af4f3
  58766836
  */
  unhex(k0, 16, "4c3752b70375de25bfbbea8831edb330");
  unhex(k1, 16, "ee37cc244fc9eb4f03519c2fcb1af4f3");
  unhex(nonce, 16, "afc7a6305610b3cf1ff0203f0f535da1");
  unhex(sigma, 16, "d39f0d73016ab2db7493307158766836");

  cf_salsa20_core(k0, k1, nonce, sigma, out);

  unhex(expect, 64, "6d2ab2a89cf0f8eea8c4becb1a6eaa9a1d1d961a961eebf9bea3fb30459033397628989db4391b5e6b2aec231b6f7272dbece8876f9b6e1218e85f9eb31330ca");
  TEST_CHECK(memcmp(expect, out, 64) == 0);

  /*
  58766836
  4fc9eb4f03519c2fcb1af4f3bfbbea88
  d39f0d73
  4c3752b70375de255610b3cf31edb330
  016ab2db
  afc7a630ee37cc241ff0203f0f535da1
  74933071
  */
  unhex(k0, 16, "4fc9eb4f03519c2fcb1af4f3bfbbea88");
  unhex(k1, 16, "afc7a630ee37cc241ff0203f0f535da1");
  unhex(nonce, 16, "4c3752b70375de255610b3cf31edb330");
  unhex(sigma, 16, "58766836d39f0d73016ab2db74933071");
  
  cf_salsa20_core(k0, k1, nonce, sigma, out);
  
  unhex(expect, 64, "b31330cadbece8876f9b6e1218e85f9e1a6eaa9a6d2ab2a89cf0f8eea8c4becb459033391d1d961a961eebf9bea3fb301b6f72727628989db4391b5e6b2aec23");
  TEST_CHECK(memcmp(expect, out, 64) == 0);

  /* From section 9. */
  for (size_t i = 0; i < 16; i++)
  {
    k0[i] = 1 + i;
    k1[i] = 201 + i;
    nonce[i] = 101 + i;
  }

  cf_salsa20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);
  
  unhex(expect, 64, "45254427290f6bc1ff8b7a06aae9d9625990b66a1533c841ef31de22d772287e68c507e1c5991f02664e4cb054f5f6b8b1a0858206489577c0c384ecea67f64a");
  TEST_CHECK(memcmp(expect, out, 64) == 0);
  
  cf_salsa20_core(k0, k0, nonce, (const uint8_t *) "expand 16-byte k", out);
  
  unhex(expect, 64, "27ad2ef81ec852113043feef25120df7f1c83d900a3732b9062ff6fd8f56bbe186556ef6a1a32bebe75eab3391d6701d0ee80510978cb78dab097ab568b6b1c1");
  TEST_CHECK(memcmp(expect, out, 64) == 0);
}

TEST_LIST = {
  { "test-salsa20", test_salsa20_core },
  { 0 }
};

