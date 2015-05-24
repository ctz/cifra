/*
 * cifra - embedded cryptography library
 * Written in 2014 by Joseph Birr-Pixton <jpixton@gmail.com>
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

#include "norx.h"
#include "handy.h"
#include "cutest.h"
#include "testutil.h"

static void test_vector(void)
{
  uint8_t K[16], N[8], H[8], P[16], C[16], A[16];

  /* This is from the paper, section A.3.1. */

  unhex(K, sizeof K, "3322110077665544bbaa9988ffeeddcc");
  unhex(N, sizeof N, "ffffffffffffffff");
  unhex(H, sizeof H, "0200001004000030");
  unhex(P, sizeof P, "07000080050000600300004001000020");

  cf_norx32_encrypt(K, N,
                    H, sizeof H,
                    P, sizeof P,
                    NULL, 0,
                    C, A);

  uint8_t expect_C[16], expect_A[16];

  unhex(expect_C, sizeof expect_C, "cd358f1f382afaca17144c72ca328722");
  unhex(expect_A, sizeof expect_A, "8aca02771052bae8ad739bfd0d3a44c0");

  TEST_CHECK(memcmp(C, expect_C, sizeof C) == 0);
  TEST_CHECK(memcmp(A, expect_A, sizeof A) == 0);

  uint8_t P2[16];
  TEST_CHECK(0 ==
             cf_norx32_decrypt(K, N,
                               H, sizeof H,
                               C, sizeof C,
                               NULL, 0,
                               A,
                               P2));

  TEST_CHECK(memcmp(P, P2, sizeof P) == 0);
  A[0] ^= 0xff;

  TEST_CHECK(cf_norx32_decrypt(K, N,
                               H, sizeof H,
                               C, sizeof C,
                               NULL, 0,
                               A,
                               P2));
}

static void test_trailer(void)
{
  /* This is one I made up, because none of the official test
   * vectors seem to use trailers. */

  uint8_t K[16], N[8], H[8], T[8], P[16], C[16], A[16];

  unhex(K, sizeof K, "3322110077665544bbaa9988ffeeddcc");
  unhex(N, sizeof N, "ffffffffffffffff");
  unhex(H, sizeof H, "0200001004000030");
  unhex(T, sizeof T, "0600005008000070");
  unhex(P, sizeof P, "07000080050000600300004001000020");

  cf_norx32_encrypt(K, N,
                    H, sizeof H,
                    P, sizeof P,
                    T, sizeof T,
                    C, A);

  uint8_t expect_C[16], expect_A[16];

  unhex(expect_C, sizeof expect_C, "cd358f1f382afaca17144c72ca328722");
  unhex(expect_A, sizeof expect_A, "6e90bc3bc28b0fb6259e9d845418c8aa");

  TEST_CHECK(memcmp(C, expect_C, sizeof C) == 0);
  TEST_CHECK(memcmp(A, expect_A, sizeof A) == 0);

  uint8_t P2[16];
  TEST_CHECK(0 ==
             cf_norx32_decrypt(K, N,
                               H, sizeof H,
                               C, sizeof C,
                               T, sizeof T,
                               A,
                               P2));

  TEST_CHECK(memcmp(P, P2, sizeof P) == 0);
  T[0] ^= 0xff;

  TEST_CHECK(cf_norx32_decrypt(K, N,
                               H, sizeof H,
                               C, sizeof C,
                               T, sizeof T,
                               A,
                               P2));
}

#include "testnorx.katdata.inc"

static void test_kat(void)
{
  uint8_t K[16], N[16], H[256], W[256];
  const uint8_t *kats = kat_data;

#define FILL(arr, c) \
  do { \
    for (size_t i = 0; i < sizeof arr; i++) \
      arr[i] = (i * c + 123) & 0xff; \
  } while (0)
  FILL(N, 181);
  FILL(K, 191);
  FILL(H, 193);
  FILL(W, 197);
#undef FILL

  for (size_t i = 0; i < sizeof W; i++)
  {
    uint8_t C[256];
    uint8_t A[16];

    cf_norx32_encrypt(K, N,
                      H, i,
                      W, i,
                      NULL, 0,
                      C, A);

    TEST_CHECK(memcmp(kats, C, i) == 0);
    kats += i;
    TEST_CHECK(memcmp(kats, A, sizeof A) == 0);
    kats += sizeof A;

    uint8_t M[256] = { 0 };
    TEST_CHECK(0 == cf_norx32_decrypt(K, N,
                                      H, i,
                                      C, i,
                                      NULL, 0,
                                      A, M));

    TEST_CHECK(0 == memcmp(M, W, i));
  }
}

TEST_LIST = {
  { "vector", test_vector },
  { "vector-trailer", test_trailer },
  { "kat", test_kat },
  { 0 }
};

