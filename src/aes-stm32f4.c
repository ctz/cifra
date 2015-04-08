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

/* This file contains an implementation of the cifra AES interface in
 * terms of the STM32F4xx cryptography processor.  It's *untested*
 * currently.
 *
 * It does not use DMA, and busy waits for encryptions to complete
 * (they're approx 14-18 cycles, so this isn't a disaster.)
 */

#include <string.h>
#include <stdlib.h>

#include "cf_config.h"
#include "aes.h"
#include "handy.h"
#include "tassert.h"

/* CRYPT Registers */
typedef struct
{
#define CRYP_CR_ENABLE           0x00008000
#define CRYP_CR_FFLUSH           0x00004000
#define CRYP_CR_KEYSIZE_AES128   0x00000000
#define CRYP_CR_KEYSIZE_AES192   0x00000100
#define CRYP_CR_KEYSIZE_AES256   0x00000200
#define CRYP_CR_DATATYPE_32B     0x00000000
#define CRYP_CR_DATATYPE_16B     0x00000040
#define CRYP_CR_DATATYPE_8B      0x00000080
#define CRYP_CR_DATATYPE_1B      0x000000c0
#define CRYP_CR_ALGO_AESECB_ENC  0x00000020
#define CRYP_CR_ALGO_AESECB_DEC  0x00000024
  uint32_t CR;    /* control */

#define CRYP_SR_IFEM 0x01
#define CRYP_SR_IFNF 0x02
#define CRYP_SR_OFNE 0x04
#define CRYP_SR_OFFU 0x08
#define CRYP_SR_BUSY 0x10
  uint32_t SR;    /* status */
  uint32_t DIN;   /* data in */
  uint32_t DOUT;  /* data out */

  /* DMA and interrupts */
  uint32_t DMACR;
  uint32_t IMSCR;
  uint32_t RISR;
  uint32_t MISR;

  /* key data */
  uint32_t K0LR;
  uint32_t K0RR;
  uint32_t K1LR;
  uint32_t K1RR;
  uint32_t K2LR;
  uint32_t K2RR;
  uint32_t K3LR;
  uint32_t K3RR;

  /* iv */
  uint32_t IV0LR;
  uint32_t IV0RR;
  uint32_t IV1LR;
  uint32_t IV1RR;
} CRYP;

static volatile CRYP *crypt = (volatile CRYP *) 0x50060000;

/* RCC registers */
typedef struct
{
  uint32_t CR;
  uint32_t PLLCFGR;
  uint32_t CFGR;
  uint32_t CIR;

  uint32_t AHB1RSTR;
  uint32_t AHB2RSTR;
  uint32_t AHB3RSTR;
  uint32_t reserved1c;
  
  uint32_t APB1RSTR;
  uint32_t APB2RSTR;
  uint32_t reserved28;
  uint32_t reserved2c;

  uint32_t AHB1ENR;
#define RCC_AHB2ENR_CRYP 0x00000010
  uint32_t AHB2ENR;
  uint32_t AHB3ENR;
  uint32_t reserved3c;
} RCC;

static volatile RCC *rcc = (volatile RCC *) 0x40023800;

void cf_aes_init(cf_aes_context *ctx, const uint8_t *key, size_t nkey)
{
  memset(ctx, 0, sizeof *ctx);

  rcc->AHB2ENR |= RCC_AHB2ENR_CRYP;

  switch (nkey)
  {
    case 16:
      ctx->rounds = AES128_ROUNDS;
      memcpy(ctx->ks, key, 16);
      break;

    case 24:
      ctx->rounds = AES192_ROUNDS;
      memcpy(ctx->ks, key, 24);
      break;

    case 32:
      ctx->rounds = AES256_ROUNDS;
      memcpy(ctx->ks, key, 32);
      break;
  }
}

static void setup_keys(const cf_aes_context *ctx, uint32_t dir)
{
  switch (ctx->rounds)
  {
    case AES128_ROUNDS:
      crypt->CR = CRYP_CR_KEYSIZE_AES128 | CRYP_CR_DATATYPE_1B | dir;
      crypt->K2LR = ctx->ks[0];
      crypt->K2RR = ctx->ks[1];
      crypt->K3LR = ctx->ks[2];
      crypt->K3RR = ctx->ks[3];
      break;

    case AES192_ROUNDS:
      crypt->CR = CRYP_CR_KEYSIZE_AES192 | CRYP_CR_DATATYPE_1B | dir;
      crypt->K1LR = ctx->ks[0];
      crypt->K1RR = ctx->ks[1];
      crypt->K2LR = ctx->ks[2];
      crypt->K2RR = ctx->ks[3];
      crypt->K3LR = ctx->ks[4];
      crypt->K3RR = ctx->ks[5];
      break;

    case AES256_ROUNDS:
      crypt->CR = CRYP_CR_KEYSIZE_AES256 | CRYP_CR_DATATYPE_1B | dir;
      crypt->K0LR = ctx->ks[0];
      crypt->K0RR = ctx->ks[1];
      crypt->K1LR = ctx->ks[2];
      crypt->K1RR = ctx->ks[3];
      crypt->K2LR = ctx->ks[4];
      crypt->K2RR = ctx->ks[5];
      crypt->K3LR = ctx->ks[6];
      crypt->K3RR = ctx->ks[7];
      break;
  }

  /* flush fifos */
  crypt->CR |= CRYP_CR_FFLUSH;
}

static void process_block(const uint8_t in[AES_BLOCKSZ],
                          uint8_t out[AES_BLOCKSZ])
{
  /* enable peripheral */
  crypt->CR |= CRYP_CR_ENABLE;

  /* since we only have one block, we don't need to deal
   * with OFNE/IFNF.  Just write the input fifo, spin
   * on BUSY and then read the results. */

  const uint32_t *inw = (const uint32_t *) in;
  uint32_t *outw = (uint32_t *) out;

  crypt->DIN = inw[0];
  crypt->DIN = inw[1];
  crypt->DIN = inw[2];
  crypt->DIN = inw[3];

  while (crypt->SR & CRYP_SR_OFNE)
    ;

  outw[0] = crypt->DOUT;
  outw[1] = crypt->DOUT;
  outw[2] = crypt->DOUT;
  outw[3] = crypt->DOUT;

  /* disable */
  crypt->CR = 0;;
}

void cf_aes_encrypt(const cf_aes_context *ctx,
                    const uint8_t in[AES_BLOCKSZ],
                    uint8_t out[AES_BLOCKSZ])
{
  setup_keys(ctx, CRYP_CR_ALGO_AESECB_ENC);
  process_block(in, out);
  crypt->CR = 0;
}

#if CF_AES_ENCRYPT_ONLY == 0
void cf_aes_decrypt(const cf_aes_context *ctx,
                    const uint8_t in[AES_BLOCKSZ],
                    uint8_t out[AES_BLOCKSZ])
{
  abort();
}
#else
void cf_aes_decrypt(const cf_aes_context *ctx,
                    const uint8_t in[AES_BLOCKSZ],
                    uint8_t out[AES_BLOCKSZ])
{
  /* NYI! */
  abort();
}
#endif

void cf_aes_finish(cf_aes_context *ctx)
{
  mem_clean(ctx, sizeof *ctx);
}

const cf_prp cf_aes = {
  .blocksz = AES_BLOCKSZ,
  .encrypt = (cf_prp_block) cf_aes_encrypt,
  .decrypt = (cf_prp_block) cf_aes_decrypt
};

