#include "handy.h"
#include "shitlisp.h"
#include "aes.h"
#include "sha2.h"
#include "hmac.h"

#include <assert.h>

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

/* Hashing */
static sl_value * hash_fn(sl_value *self, sl_value *args, sl_symboltab *tab, const cf_chash *h)
{
  sl_iter it = sl_iter_start(args);
  sl_value *msg = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);

  if (!msg)
    return sl_get_nil();

  cf_chash_ctx ctx;
  assert(h->ctxsz <= CF_CHASH_MAXCTX);
  h->init(&ctx);
  h->update(&ctx, msg->u.bytes.buf, msg->u.bytes.len);
  sl_decref(msg);

  uint8_t result[CF_MAXHASH];
  assert(h->hashsz <= CF_MAXHASH);
  h->final(&ctx, result);

  return sl_new_bytes(result, h->hashsz);
}

static sl_value * sha224(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return hash_fn(self, args, tab, &cf_sha224);
}

static sl_value * sha256(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return hash_fn(self, args, tab, &cf_sha256);
}

/* HMAC */
static sl_value * hmac_fn(sl_value *self, sl_value *args, sl_symboltab *tab, const cf_chash *h)
{
  sl_iter it = sl_iter_start(args);
  sl_value *key = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);
  sl_value *msg = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);

  if (!key || !msg)
  {
    sl_decref(key);
    sl_decref(msg);
    return sl_get_nil();
  }

  uint8_t result[CF_MAXHASH];
  cf_hmac(key->u.bytes.buf, key->u.bytes.len,
          msg->u.bytes.buf, msg->u.bytes.len,
          result,
          h);

  sl_decref(key);
  sl_decref(msg);
  return sl_new_bytes(result, h->hashsz);
}

static sl_value * hmac_sha224(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return hmac_fn(self, args, tab, &cf_sha224);
}

static sl_value * hmac_sha256(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return hmac_fn(self, args, tab, &cf_sha256);
}

int SL_MODULE_ENTRY(sl_symboltab *tab)
{
  ER(sl_symboltab_add_name_native(tab, "aes-encrypt", aes_block_encrypt));
  ER(sl_symboltab_add_name_native(tab, "aes-decrypt", aes_block_decrypt));
  ER(sl_symboltab_add_name_native(tab, "sha224", sha224));
  ER(sl_symboltab_add_name_native(tab, "sha256", sha256));
  ER(sl_symboltab_add_name_native(tab, "hmac-sha224", hmac_sha224));
  ER(sl_symboltab_add_name_native(tab, "hmac-sha256", hmac_sha256));
  return 0;
}
