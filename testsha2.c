#include "sha2.h"
#include "../bignum/handy.h"
#include "ext/cutest.h"

static void test_sha256_inter(void)
{
  uint8_t digest[32] = { 0 };
  sha256_context ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, "abc", 3);
  sha256_digest(&ctx, digest);

  sha256_init(&ctx);
  sha256_update(&ctx, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
  sha256_digest(&ctx, digest);
}

TEST_LIST = {
  { "sha256-intermediate", test_sha256_inter },
  { 0 }
};

