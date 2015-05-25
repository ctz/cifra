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

#include "chacha20poly1305.h"
#include "handy.h"
#include "cutest.h"
#include "testutil.h"

static void test_vector(void)
{
  uint8_t K[32], N[8], H[10], P[10], C[10], A[16];

  /* This is from the draft (v4) section 7. */

  unhex(K, sizeof K, "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007");
  unhex(N, sizeof N, "cd7cf67be39c794a");
  unhex(H, sizeof H, "87e229d4500845a079c0");
  unhex(P, sizeof P, "86d09974840bded2a5ca");

  cf_chacha20poly1305_encrypt(K, N,
                              H, sizeof H,
                              P, sizeof P,
                              C, A);

  uint8_t expect_C[10], expect_A[16];

  unhex(expect_C, sizeof expect_C, "e3e446f7ede9a19b62a4");
  unhex(expect_A, sizeof expect_A, "677dabf4e3d24b876bb284753896e1d6");

  TEST_CHECK(memcmp(C, expect_C, sizeof C) == 0);
  TEST_CHECK(memcmp(A, expect_A, sizeof A) == 0);

  uint8_t P2[10];
  TEST_CHECK(0 == cf_chacha20poly1305_decrypt(K, N,
                                              H, sizeof H,
                                              C, sizeof C,
                                              A, P2));
  TEST_CHECK(memcmp(P2, P, sizeof P2) == 0);

  /* check failure */
  C[0] ^= 0xff;
  TEST_CHECK(0 != cf_chacha20poly1305_decrypt(K, N,
                                              H, sizeof H,
                                              C, sizeof C,
                                              A, P2));

}

TEST_LIST = {
  { "vector", test_vector },
  { 0 }
};

