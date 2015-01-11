#include "sha2.h"
#include "../bignum/handy.h"
#include "cutest.h"
#include "testutil.h"

#undef REALLY_SLOW_TEST

static void test_sha256_inter(void)
{
  uint8_t digest[32] = { 0 };
  cf_sha256_context ctx;
  cf_sha256_init(&ctx);
  cf_sha256_update(&ctx, "abc", 3);
  cf_sha256_digest_final(&ctx, digest);

  cf_sha256_init(&ctx);
  cf_sha256_update(&ctx, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
  cf_sha256_digest(&ctx, digest);
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

  for (size_t i = 0; i < sizeof digest; i++)
    printf("%02x", digest[i]);
  printf("\n");
}
#endif

TEST_LIST = {
  { "sha256-intermediate", test_sha256_inter },
#ifdef REALLY_SLOW_TEST
  { "sha256-long", test_sha256_long },
#endif
  { 0 }
};

