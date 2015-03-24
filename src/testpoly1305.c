
#include "poly1305.h"

#include "testutil.h"
#include "handy.h"
#include "cutest.h"

static void check(const char *rstr, const char *sstr,
                  const char *msgstr, const char *tagstr)
{
  uint8_t r[16], s[16], tag[16];
  uint8_t msg[132], out[16];

  unhex(r, sizeof r, rstr);
  unhex(s, sizeof s, sstr);
  size_t nmsg = unhex(msg, sizeof msg, msgstr);
  unhex(tag, sizeof tag, tagstr);

  cf_poly1305 ctx;
  cf_poly1305_init(&ctx, r, s);
  cf_poly1305_update(&ctx, msg, nmsg);
  cf_poly1305_finish(&ctx, out);

  TEST_CHECK(memcmp(out, tag, 16) == 0);
}

static void test_poly1305(void)
{
  check("eea6a7251c1e72916d11c2cb214d3c25",
        "2539121d8e234e652d651fa4c8cff880",
        "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5",
        "f3ffc7703f9400e52a7dfb4b3d3305d9");

  check("851fc40c3467ac0be05cc20404f3f700",
        "580b3b0f9447bb1e69d095b5928b6dbc",
        "f3f6",
        "f4c633c3044fc145f84f335cb81953de");

  check("a0f3080000f46400d0c7e9076c834403",
        "dd3fab2251f11ac759f0887129cc2ee7",
        "",
        "dd3fab2251f11ac759f0887129cc2ee7");
  
  check("48443d0bb0d21109c89a100b5ce2c208",
        "83149c69b561dd88298a1798b10716ef",
        "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136",
        "0ee1c16bb73f0f4fd19881753c01cdbe");

  check("12976a08c4426d0ce8a82407c4f48207",
        "80f8c20aa71202d1e29179cbcb555a57",
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9",
        "5154ad0d2cb26e01274fc51148491f1b");
}

TEST_LIST = {
  { "poly1305", test_poly1305 },
  { 0 }
};
