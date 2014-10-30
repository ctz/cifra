#include "handy.h"
#include "shitlisp.h"
#include "aes.h"

static sl_value * aes_block_fn(sl_value *self, sl_value *args, sl_symboltab *tab,
                               void (*blockfn)(const aes_context *ctx,
                                               const uint8_t *in,
                                               uint8_t *out))
{
  sl_iter it = sl_iter_start(args);
  sl_value *key = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);
  sl_value *block = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);

  sl_value *ret = NULL;

  if (!key || !block ||
      (key->u.bytes.len != 16 && key->u.bytes.len != 24 && key->u.bytes.len != 32) ||
      block->u.bytes.len != AES_BLOCKSZ)
  {
    ret = sl_get_nil();
    goto x_err;
  }

  aes_context ctx;
  aes_init(&ctx, key->u.bytes.buf, key->u.bytes.len);
  uint8_t blockout[AES_BLOCKSZ];
  blockfn(&ctx, block->u.bytes.buf, blockout);
  ret = sl_new_bytes(blockout, AES_BLOCKSZ);
  aes_finish(&ctx);

x_err:
  sl_decref(key);
  sl_decref(block);
  return ret;
}

static sl_value * aes_block_encrypt(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return aes_block_fn(self, args, tab, aes_encrypt);
}

static sl_value * aes_block_decrypt(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return aes_block_fn(self, args, tab, aes_decrypt);
}

int SL_MODULE_ENTRY(sl_symboltab *tab)
{
  ER(sl_symboltab_add_name_native(tab, "aes-encrypt", aes_block_encrypt));
  ER(sl_symboltab_add_name_native(tab, "aes-decrypt", aes_block_decrypt));
  return 0;
}
