#include "sha1.h"
#include "handy.h"
#include "cutest.h"
#include "testutil.h"

static void test_sha1(void)
{
  uint8_t out[20];
  cf_sha1_context ctx;
  cf_sha1_init(&ctx);
  cf_sha1_update(&ctx, "", 0);
  cf_sha1_digest_final(&ctx, out);

  dump("sha1", out, sizeof out);
}

TEST_LIST = {
  { "sha1", test_sha1},
  { 0 }
};

