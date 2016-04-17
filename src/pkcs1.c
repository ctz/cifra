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

#include <string.h>

#include "pkcs1.h"
#include "bitops.h"
#include "handy.h"
#include "tassert.h"

#define MAX_MODULUS 2048/8

/* Run MGF1 with given hash function, XORing result into
 * output_xor. */
static void MGF1_xor(const cf_chash *hash,
                     const uint8_t *input, size_t ninput,
                     uint8_t *output_xor, size_t noutput)
{
  uint8_t buf[CF_MAXHASH];
  uint32_t counter = 0;

  while (noutput)
  {
    write32_be(counter, buf);

    cf_chash_ctx ctx;
    hash->init(&ctx);
    hash->update(&ctx, input, ninput);
    hash->update(&ctx, buf, 4);
    hash->digest(&ctx, buf);

    size_t need = MIN(hash->hashsz, noutput);
    xor_bb(output_xor, output_xor, buf, need);
    output_xor += need;
    noutput -= need;
    counter++;
  }
}

unsigned cf_rsaes_oaep_can_encode(const cf_chash *hash,
                                  size_t nmessage, size_t nmodulus)
{
  size_t min_overhead = 2 * hash->hashsz + 2;
  return (nmessage + min_overhead <= nmodulus);
}

void cf_rsaes_oaep_encode(const cf_chash *hash, cf_rng *rng,
                          const uint8_t *message, size_t nmessage,
                          uint8_t *enc_out, size_t nmodulus)
{
  size_t hLen = hash->hashsz;
  assert(cf_rsaes_oaep_can_encode(hash, nmessage, nmodulus));

  /* a. If the label L is not provided, let L be the empty string. Let
   *    lHash = Hash(L), an octet string of length hLen. */
  uint8_t lHash[CF_MAXHASH];
  cf_hash(hash, NULL, 0, lHash);

  /* b. Generate an octet string PS consisting of k - mLen - 2hLen - 2
   *    zero octets.  The length of PS may be zero. */
  /* c. Concatenate lHash, PS, a single octet with hexadecimal value
   *    0x01, and the message M to form a data block DB of length k - hLen - 1
   *    octets as
   *
   *      DB = lHash || PS || 0x01 || M
   */
  uint8_t *DB = enc_out + 1 + hLen,
          *PS = DB + hLen;
  size_t PSlen = nmodulus - nmessage - 2 * hLen - 1;

  memcpy(DB, lHash, hLen);
  memset(PS, 0, PSlen);
  PS[PSlen] = 0x01;
  memcpy(PS + 1, message, nmessage);

  /* d. Generate a random octet string seed of length hLen. */
  uint8_t seed[CF_MAXHASH];
  rng->generate(rng, seed, hLen);

  /* e. Let dbMask = MGF(seed, k - hLen - 1) */
  /* f. Let maskedDB = DB \xor dbMask */
  uint8_t *maskedDB = DB;
  size_t DBlen = nmodulus - hLen - 1;
  MGF1_xor(hash,
           seed, hLen,
           maskedDB, DBlen);

  /* g. Let seedMask = MGF(maskedDB, hLen) */
  /* h. Let maskedSeed = seed \xor seedMask */
  uint8_t *maskedSeed = enc_out + 1;
  memcpy(maskedSeed, seed, hLen);
  MGF1_xor(hash,
           maskedDB, DBlen,
           maskedSeed, hLen);

  /* i. Concatenate a single octet with hexadecimal value 0x00,
   *    maskedSeed, and maskedDB to form an encoded message EM
   *    of length k octets as
   *      EM = 0x00 || maskedSeed || maskedDB
   * [our placement of maskedSeed and maskedDB above achieves this]
   */
  enc_out[0] = 0x00;
}

/* message_out must be nmodulus bytes, *nmessage contains the valid
 * prefix of the message. */
unsigned cf_rsaes_oaep_decode(const cf_chash *hash,
                              const uint8_t *enc, size_t nmodulus,
                              uint8_t *message_out, size_t *nmessage)
{
  size_t hLen = hash->hashsz;
  assert(nmodulus >= hLen * 2 + 2);

  /* a. If the label L is not provided, let L be the empty string. Let
   *    lHash = Hash(L), an octet string of length hLen */
  uint8_t lHash[CF_MAXHASH];
  cf_hash(hash, NULL, 0, lHash);

  /* b. Seperate the encoded message EM into a single octet Y, an octet
   *    string maskedSeed of length hLen, and an octet string maskedDb
   *    of length k - hLen - 1 as
   *      EM = Y || maskedSeed || maskedDB
   */
  uint8_t Y = enc[0];
  size_t maskedDBlen = nmodulus - hLen - 1;
  const uint8_t *maskedSeed = enc + 1,
                *maskedDB = enc + 1 + hLen;

  /* c. Let seedMask = MGF(maskedDB, hLen). */
  /* d. Let seed = maskedSeed \xor seedMask. */
  uint8_t seed[CF_MAXHASH];
  memcpy(seed, maskedSeed, hLen);
  MGF1_xor(hash,
           maskedDB, maskedDBlen,
           seed, hLen);

  /* e. Let dbMask = MGF(seed, k - hLen - 1) */
  /* f. DB = maskedDB \xor dbMask */
  uint8_t *DB = message_out;
  memcpy(DB, maskedDB, maskedDBlen);
  MGF1_xor(hash,
           seed, hLen,
           DB, maskedDBlen);

  /* g. Separate DB into an octet string lHash' of length hLen, a
   *    (possibly empty) padding string PS consisting of octets with
   *    hexadecimal value 0x00, and a message M as
   *      DB = lHash' || PS || 0x01 || M
   */
  const uint8_t *lHashPrime = DB,
                *PS = DB + hLen,
                *PSend = DB + maskedDBlen;

  unsigned valid = 1,
           in_m = 0;
  *nmessage = 0;

  for (const uint8_t *p = PS; p != PSend; p++)
  {
    if (in_m)
    {
      *message_out = *p;
      message_out++;
      (*nmessage)++;
    } else if (*p == 0x00) {
      /* PS, ok */
    } else if (*p == 0x01) {
      /* seperator, ok */
      in_m = 1;
    } else {
      valid = 0;
    }
  }

  /* invalid if we got no M */
  valid &= in_m;

  /* invalid if lHash' != lHash */
  valid &= mem_eq(lHash, lHashPrime, hLen);

  /* invalid if Y non-zero */
  valid &= (Y == 0x00);

  return !valid;
}

unsigned cf_rsaes_pkcs1_can_encode(size_t nmessage, size_t nmodulus)
{
  size_t min_overhead = 3 + 8;
  return (nmessage + min_overhead <= nmodulus);
}

void cf_rsaes_pkcs1_encode(cf_rng *rng,
                           const uint8_t *message, size_t nmessage,
                           uint8_t *enc_out, size_t nmodulus)
{
  assert(cf_rsaes_pkcs1_can_encode(nmessage, nmodulus));

  enc_out[0] = 0x00;
  enc_out[1] = 0x02;

  uint8_t *PS = enc_out + 2;
  size_t PSlen = nmodulus - nmessage - 3;
  rng->generate(rng, PS, PSlen);

  for (size_t i = 0; i < PSlen; i++)
    while (PS[i] == 0x00)
      rng->generate(rng, &PS[i], 1);

  enc_out[2 + PSlen] = 0x00;
  memcpy(enc_out + 3 + PSlen, message, nmessage);
  assert(nmodulus == 3 + PSlen + nmessage);
}

unsigned cf_rsaes_pkcs1_decode(const uint8_t *enc, size_t nmodulus,
                               uint8_t *message_out, size_t *nmessage)
{
  *nmessage = 0;

  unsigned valid = 1, ps_done = 0;

  valid &= enc[0] == 0x00;
  valid &= enc[1] == 0x02;

  for (size_t i = 2; i < nmodulus; i++)
  {
    if (ps_done)
    {
      *message_out = enc[i];
      message_out++;
      (*nmessage)++;
    } else if (enc[i] == 0x00) {
      ps_done = 1;
    }
  }

  valid &= ps_done;
  return !valid;
}

unsigned cf_rsassa_pkcs1_can_encode(size_t nmessage, size_t nmodulus)
{
  return cf_rsaes_pkcs1_can_encode(nmessage, nmodulus);
}

void cf_rsassa_pkcs1_encode(const uint8_t *message, size_t nmessage,
                            uint8_t *enc_out, size_t nmodulus)
{
  assert(cf_rsassa_pkcs1_can_encode(nmessage, nmodulus));

  enc_out[0] = 0x00;
  enc_out[1] = 0x01;

  uint8_t *PS = enc_out + 2;
  size_t PSlen = nmodulus - nmessage - 3;
  memset(PS, 0xff, PSlen);

  enc_out[2 + PSlen] = 0x00;

  memcpy(enc_out + 3 + PSlen, message, nmessage);
}

unsigned cf_rsassa_pkcs1_verify(const uint8_t *enc, size_t nmodulus,
                                const uint8_t *message, size_t nmessage)
{
  uint8_t expect[MAX_MODULUS];
  assert(MAX_MODULUS <= nmodulus);

  cf_rsassa_pkcs1_encode(message, nmessage, expect, nmodulus);
  return !mem_eq(expect, enc, nmodulus);
}

unsigned cf_rsassa_pss_can_encode(const cf_chash *hash, size_t nmodulus)
{
  size_t emlen = hash->hashsz * 2 + 2;
  return (emlen <= nmodulus);
}

/* nb. fixes sLen = hLen */
void cf_rsassa_pss_encode(const cf_chash *hash, cf_rng *rng,
                          const uint8_t *msghash, /* of size hash->hashsz */
                          uint8_t *enc_out, size_t nmodulus)
{
  size_t hLen = hash->hashsz,
         sLen = hLen;

  assert(cf_rsassa_pss_can_encode(hash, nmodulus));

  /* 4. Generate a random octet string salt of length sLen. */
  uint8_t salt[CF_MAXHASH];
  rng->generate(rng, salt, sLen);

  /* 5. Let M' = 0x00 00 00 00 00 00 00 00 || mHash || salt */
  /* 6. Let H = Hash(M') */
  const uint8_t eight_zeroes[8] = { 0 };
  uint8_t H[CF_MAXHASH];
  cf_chash_ctx ctx;
  hash->init(&ctx);
  hash->update(&ctx, eight_zeroes, sizeof eight_zeroes);
  hash->update(&ctx, msghash, hLen);
  hash->update(&ctx, salt, sLen);
  hash->digest(&ctx, H);

  /* 7. Generate an octet string PS consisting of emLen - sLen - hLen - 2
   *    zero octets.  The length of PS may be 0. */
  uint8_t *PS = enc_out;
  size_t PSlen = nmodulus - sLen - hLen - 2;
  memset(PS, 0x00, PSlen);

  /* 8. Let DB = PS || 0x01 || salt */
  uint8_t *DB = PS;
  size_t DBlen = PSlen + sLen + 1;
  DB[PSlen] = 0x01;
  memcpy(DB + PSlen + 1, salt, sLen);

  /* 9. Let dbMask = MGF(H, emLen - hLen - 1) */
  /* 10. Let maskedDB = DB \xor dbMask */
  MGF1_xor(hash,
           H, hLen,
           DB, DBlen);

  /* 11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
   *     maskedDB to zero
   *     [we only support multiple-8 moduli, meaning emBits is
   *      fixed as emLen + 7 / 8 - 1] */
  DB[0] &= 0x7f;

  /* 12. Let EM = maskedDB || H || 0xbc */
  memcpy(DB + DBlen, H, hLen);
  DB[DBlen + hLen] = 0xbc;
}

unsigned cf_rsassa_pss_verify(const cf_chash *hash,
                              const uint8_t *msghash,
                              const uint8_t *enc, size_t nmodulus)
{
  size_t hLen = hash->hashsz,
         sLen = hash->hashsz;

  assert(cf_rsassa_pss_can_encode(hash, nmodulus));

  /* 4. If the rightmost octet of EM does not have hexadecimal value
   *    0xbc output "inconsistent" and stop. */
  if (enc[nmodulus - 1] != 0xbc)
    return 1;

  /* 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
   *    and let H be the next hLen octets */
  size_t DBlen = nmodulus - hLen - 1;
  const uint8_t *maskedDB = enc,
                *H = enc + DBlen;

  /* 6. If the leftmost 8emLen - emBits bits of the leftmost octet in
   *    maskedDB are not all equal to zero, output "inconsistent" and
   *    stop.
   *    [see above] */
  uint8_t DB[MAX_MODULUS];
  memcpy(DB, maskedDB, DBlen);
  DB[0] &= 0x7f;

  /* 7. Let dbMask = MGF(H, emLen - hLen - 1) */
  /* 8. Let DB = maskedDB \xor dbMask */
  MGF1_xor(hash,
           H, hLen,
           DB, DBlen);

  /* 9. Set the leftmost 8emLen - emBits bits of the leftmost octet in DB
   *    to zero.*/
  DB[0] &= 0x7f;

  /* 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
   *     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
   *     position is "position 1") does not have hexadecimal value 0x01,
   *     output "inconsistent" and stop. */
  size_t PSlen = DBlen - sLen - 1;
  for (size_t i = 0; i < PSlen; i++)
    if (DB[i] != 0x00)
      return 1;
  if (DB[PSlen] != 0x01)
    return 1;

  /* 11. Let salt be the last sLen octets of DB */
  const uint8_t *salt = DB + DBlen - sLen;

  /* 12. Let
   *       M' = 0x00 00 00 00 00 00 00 00 || mHash || salt */
  /* 13. Let H' = Hash(M') */
  const uint8_t eight_zeroes[8] = { 0x00 };
  uint8_t Hprime[CF_MAXHASH];
  cf_chash_ctx ctx;
  hash->init(&ctx);
  hash->update(&ctx, eight_zeroes, sizeof eight_zeroes);
  hash->update(&ctx, msghash, hLen);
  hash->update(&ctx, salt, sLen);
  hash->digest(&ctx, Hprime);

  /* 14. If H = H' output "consistent", otherwise output "inconsistent" */
  return memcmp(H, Hprime, hLen) != 0;
}

