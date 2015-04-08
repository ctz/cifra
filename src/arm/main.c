#ifndef TEST
# error You must select a function to test.
#endif

#include "semihost.h"
#include "aes.h"
#include "sha2.h"
#include "sha3.h"
#include "modes.h"
#include "salsa20.h"
#include "curve25519.h"

#include <stdio.h>

typedef void (*measure_fn)(void);

static void do_nothing(void)
{
}

static void stack_64w(void)
{
  volatile uint32_t words[64];
  words[0] = 0;
  words[63] = 0;
  (void) words[63];
}

static void stack_8w(void)
{
  volatile uint32_t words[8];
  words[0] = 0;
  words[7] = 0;
  (void) words[7];
}

static void hashtest_sha256(void)
{
  uint8_t hash[CF_SHA256_HASHSZ];
  cf_sha256_context ctx;
  cf_sha256_init(&ctx);
  cf_sha256_update(&ctx, "", 0);
  cf_sha256_digest_final(&ctx, hash);
}

static void hashtest_sha512(void)
{
  uint8_t hash[CF_SHA512_HASHSZ];
  cf_sha512_context ctx;
  cf_sha512_init(&ctx);
  cf_sha512_update(&ctx, "", 0);
  cf_sha512_digest_final(&ctx, hash);
}

static void hashtest_sha3_256(void)
{
  uint8_t hash[CF_SHA3_256_HASHSZ];
  cf_sha3_context ctx;
  cf_sha3_256_init(&ctx);
  cf_sha3_256_update(&ctx, "", 0);
  cf_sha3_256_digest_final(&ctx, hash);
}

static void hashtest_sha3_512(void)
{
  uint8_t hash[CF_SHA3_512_HASHSZ];
  cf_sha3_context ctx;
  cf_sha3_512_init(&ctx);
  cf_sha3_512_update(&ctx, "", 0);
  cf_sha3_512_digest_final(&ctx, hash);
}

static void aes128block_test(void)
{
  uint8_t key[16] = { 0 }, block[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);
  cf_aes_encrypt(&ctx, block, block);
  emit("result = ");
  emit_hex(block, sizeof block);
  emit("\n");
}

static void aes128sched_test(void)
{
  uint8_t key[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);
}

static void aes256block_test(void)
{
  uint8_t key[32] = { 0 }, block[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);
  cf_aes_encrypt(&ctx, block, block);
}

static void aes256sched_test(void)
{
  uint8_t key[32] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);
}

static void aes128gcm_test(void)
{
  uint8_t key[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);

  uint8_t msg[16] = { 0 };
  uint8_t aad[16] = { 0 };
  uint8_t nonce[12] = { 0 };
  uint8_t cipher[16] = { 0 };
  uint8_t tag[16] = { 0 };

  cf_gcm_encrypt(&cf_aes, &ctx,
                 msg, sizeof msg,
                 aad, sizeof aad,
                 nonce, sizeof nonce,
                 cipher,
                 tag, sizeof tag);
}

static void aes128eax_test(void)
{
  uint8_t key[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);

  uint8_t msg[16] = { 0 };
  uint8_t aad[16] = { 0 };
  uint8_t nonce[12] = { 0 };
  uint8_t cipher[16] = { 0 };
  uint8_t tag[16] = { 0 };

  cf_eax_encrypt(&cf_aes, &ctx,
                 msg, sizeof msg,
                 aad, sizeof aad,
                 nonce, sizeof nonce,
                 cipher,
                 tag, sizeof tag);
}

static void aes128ccm_test(void)
{
  uint8_t key[16] = { 0 };
  cf_aes_context ctx;
  cf_aes_init(&ctx, key, sizeof key);

  uint8_t msg[16] = { 0 };
  uint8_t aad[16] = { 0 };
  uint8_t nonce[11] = { 0 };
  uint8_t cipher[16] = { 0 };
  uint8_t tag[16] = { 0 };

  cf_ccm_encrypt(&cf_aes, &ctx,
                 msg, sizeof msg, 4,
                 aad, sizeof aad,
                 nonce, sizeof nonce,
                 cipher,
                 tag, sizeof tag);
}

static void salsa20_test(void)
{
  uint8_t key[32] = { 0 };
  uint8_t nonce[8] = { 0 };
  uint8_t msg[64] = { 0 };
  uint8_t cipher[64] = { 0 };

  cf_salsa20_ctx ctx;
  cf_salsa20_init(&ctx, key, sizeof key, nonce);
  cf_salsa20_cipher(&ctx, msg, cipher, sizeof msg);
}

static void chacha20_test(void)
{
  uint8_t key[32] = { 0 };
  uint8_t nonce[8] = { 0 };
  uint8_t msg[64] = { 0 };
  uint8_t cipher[64] = { 0 };

  cf_chacha20_ctx ctx;
  cf_chacha20_init(&ctx, key, sizeof key, nonce);
  cf_chacha20_cipher(&ctx, msg, cipher, sizeof msg);
}

static void curve25519_test(void)
{
  uint8_t secret[32] = { 1 };
  uint8_t pubkey[32];
  cf_curve25519_mul_base(pubkey, secret);
}

/* Provided by linkscript */
extern uint32_t __HeapLimit;

#define STACK_MAGIC 0x57ac57ac

static inline void clear_stack(void)
{
  uint32_t *stack_start = &__HeapLimit;
  uint32_t ss, *stack_stop = &ss;
  size_t words = stack_stop - stack_start;
  for (size_t i = 0; i < words; i++)
    stack_start[i] = STACK_MAGIC;
}

static inline uint32_t measure_stack(void)
{
  uint32_t *stack_start = &__HeapLimit;
  uint32_t ss, *stack_stop = &ss;
  size_t words = stack_stop - stack_start;
  for (size_t i = 0; i < words; i++)
    if (stack_start[i] != STACK_MAGIC)
      return words - i + 4; /* we used 4 words for ourselves, roughly */

  return 0;
}

static void measure(measure_fn fn)
{
  clear_stack();
  uint32_t start_cycles = reset_cycles();
  fn();
  uint32_t end_cycles = get_cycles();
  uint32_t stack_words = measure_stack();

  emit("cycles = ");
  emit_uint32(end_cycles - start_cycles);
  emit("\n");
  emit("stack = ");
  emit_uint32(stack_words << 2);
  emit("\n");

}

#define STRING_(x) #x
#define STRING(x) STRING_(x)

int main(void)
{
  emit(STRING(TEST) "\n");
  measure(TEST);
  quit_success();

  (void) do_nothing;
  (void) stack_8w;
  (void) stack_64w;
  (void) hashtest_sha256;
  (void) hashtest_sha512;
  (void) hashtest_sha3_256;
  (void) hashtest_sha3_512;
  (void) aes128block_test;
  (void) aes128sched_test;
  (void) aes256block_test;
  (void) aes256sched_test;
  (void) aes128gcm_test;
  (void) aes128eax_test;
  (void) aes128ccm_test;
  (void) salsa20_test;
  (void) chacha20_test;
  (void) curve25519_test;
}
