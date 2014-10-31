#include "sha2.h"
#include "../bignum/handy.h"
#include "ext/cutest.h"

static void test_sha256_inter(void)
{
  uint8_t digest[32] = { 0 };
  cf_sha256_context ctx;
  cf_sha256_init(&ctx);
  cf_sha256_update(&ctx, "abc", 3);
  cf_sha256_final(&ctx, digest);

  cf_sha256_init(&ctx);
  cf_sha256_update(&ctx, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
  cf_sha256_final(&ctx, digest);
}

TEST_LIST = {
  { "sha256-intermediate", test_sha256_inter },
  { 0 }
};

