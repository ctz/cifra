#include "semihost.h"
#include "sha2.h"

#include <stdio.h>

typedef void (*measure_fn)(void *ctx);

static void do_nothing(void *v)
{
}

static void stack_64w(void *v)
{
  volatile uint32_t words[64];
  words[63] = 0;
  (void) words[63];
}

static void stack_8w(void *v)
{
  volatile uint32_t words[8];
  words[7] = 0;
  (void) words[7];
}

static void hashtest_sha256(void *v)
{
  uint8_t hash[CF_SHA256_HASHSZ];
  cf_sha256_context ctx;
  cf_sha256_init(&ctx);
  cf_sha256_update(&ctx, "", 0);
  cf_sha256_digest_final(&ctx, hash);
}

static void hashtest_sha512(void *v)
{
  uint8_t hash[CF_SHA512_HASHSZ];
  cf_sha512_context ctx;
  cf_sha512_init(&ctx);
  cf_sha512_update(&ctx, "", 0);
  cf_sha512_digest_final(&ctx, hash);
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

static void measure(measure_fn fn, void *ctx)
{
  clear_stack();
  uint32_t start_cycles = reset_cycles();
  fn(ctx);
  uint32_t end_cycles = get_cycles();
  uint32_t stack_words = measure_stack();

  emit("cycles = ");
  emit_uint32(end_cycles - start_cycles);
  emit("\n");
  emit("stack = ");
  emit_uint32(stack_words);
  emit("\n");

}

int main(void)
{
  emit("do_nothing:\n");
  measure(do_nothing, NULL);
  emit("stack_8w:\n");
  measure(stack_8w, NULL);
  emit("stack_64w:\n");
  measure(stack_64w, NULL);
  emit("hashtest_sha256:\n");
  measure(hashtest_sha256, NULL);
  emit("hashtest_sha512:\n");
  measure(hashtest_sha512, NULL);

  quit_success();
}
