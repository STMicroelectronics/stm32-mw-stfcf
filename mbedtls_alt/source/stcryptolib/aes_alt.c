/**
  ******************************************************************************
  * @file    aes_alt.c
  * @brief   Implementation of mbedtls_alt AES module
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  * Copyright The Mbed TLS Contributors
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/**
  * This file implements AES block cipher based on STM32 crypto library.
  *
  * FIPS-197 compliant AES implementation
  * The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
  *
  * http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
  * http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
  */

/* Includes ------------------------------------------------------------------*/
#include "common.h"

#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_AES_ALT)
#include <string.h>
#include "mbedtls/aes.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_STCRYPTOLIB_AES_ALT)

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/

/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_AES_ALT_FUNCTIONS STCRYPTOLIB AES Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief Public API functions for STCRYPTOLIB AES alternate implementation.
  * @{
  */

/** @cond DOXYGEN_SHOULD_SKIP_THIS */
/**
  * @brief Convert return value from STCryptoLib to MBED
  */
static int aes_mbed_return_value(cmox_cipher_retval_t retval)
{
  int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR; /* return value */

  switch (retval)
  {
    case CMOX_CIPHER_SUCCESS:
      ret = 0;
      break;

    case CMOX_CIPHER_ERR_INTERNAL:
      ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;
      break;

    case CMOX_CIPHER_ERR_NOT_IMPLEMENTED:
      ret = MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
      break;

    case CMOX_CIPHER_ERR_BAD_PARAMETER:
      ret = MBEDTLS_ERR_AES_BAD_INPUT_DATA;
      break;

    case CMOX_CIPHER_ERR_BAD_OPERATION:
      ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;
      break;

    case CMOX_CIPHER_ERR_BAD_INPUT_SIZE:
      ret = MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
      break;

    case CMOX_CIPHER_AUTH_SUCCESS:
      ret = 0;
      break;

    case CMOX_CIPHER_AUTH_FAIL:
      ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;
      break;

    default :
      ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;
      break;
  }
  return ret;
}

static int aes_set_key(mbedtls_aes_context *ctx, const unsigned char *key,
                       unsigned int keybits)
{
  mbedtls_aes_init(ctx);

  /* Store key in ctx but not in cmox_ctx (waiting for construct) */
  if (keybits > 256U)
  {
    return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
  }

  (void) memcpy(ctx->aes_key, key, keybits / 8U);
  ctx->aes_key_size = keybits / 8U;

  return 0;
}

/* Implementation that must never be optimized out by the compiler */
static void mbedtls_zeroize(void *value, size_t size)
{
  volatile unsigned char *p = (unsigned char *)value;
  while (size > 0U)
  {
    *p = 0;
    p++;
    size--;
  }
}
/** @endcond */

void mbedtls_aes_init(mbedtls_aes_context *ctx)
{
  (void)memset(ctx, 0, sizeof(mbedtls_aes_context));
  /* Init the STCryptoLib */
  cmox_init_arg_t init_arg;

  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  (void)cmox_initialize(&init_arg);
}

void mbedtls_aes_free(mbedtls_aes_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }

  mbedtls_zeroize(ctx, sizeof(mbedtls_aes_context));
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
void mbedtls_aes_xts_init(mbedtls_aes_xts_context *ctx)
{
  mbedtls_aes_init(&ctx->crypt);
  mbedtls_aes_init(&ctx->tweak);
}

void mbedtls_aes_xts_free(mbedtls_aes_xts_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }

  mbedtls_aes_free(&ctx->crypt);
  mbedtls_aes_free(&ctx->tweak);
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

/**
  * @brief AES key schedule (encryption)
  */
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
  return aes_set_key(ctx, key, keybits);
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
/** @cond DOXYGEN_SHOULD_SKIP_THIS */
static int mbedtls_aes_xts_decode_keys(const unsigned char *key,
                                       unsigned int keybits,
                                       const unsigned char **key1,
                                       unsigned int *key1bits,
                                       const unsigned char **key2,
                                       unsigned int *key2bits)
{
  const unsigned int half_keybits = keybits / 2U;
  const unsigned int half_keybytes = half_keybits / 8U;

  switch (keybits)
  {
    case 256:
      break;
    case 512:
      break;
    default:
      return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
      break;
  }

  *key1bits = half_keybits;
  *key2bits = half_keybits;
  *key1 = &key[0];
  *key2 = &key[half_keybytes];

  return 0;
}
/** @endcond */

int mbedtls_aes_xts_setkey_enc(mbedtls_aes_xts_context *ctx,
                               const unsigned char *key,
                               unsigned int keybits)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  const unsigned char *key1, *key2;
  unsigned int key1bits, key2bits;

  ret = mbedtls_aes_xts_decode_keys(key, keybits, &key1, &key1bits,
                                    &key2, &key2bits);
  if (ret != 0)
  {
    return ret;
  }

  /* Set the tweak key. Always set tweak key for the encryption mode. */
  ret = mbedtls_aes_setkey_enc(&ctx->tweak, key2, key2bits);
  if (ret != 0)
  {
    return ret;
  }

  /* Set crypt key for encryption. */
  return mbedtls_aes_setkey_enc(&ctx->crypt, key1, key1bits);
}

int mbedtls_aes_xts_setkey_dec(mbedtls_aes_xts_context *ctx,
                               const unsigned char *key,
                               unsigned int keybits)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  const unsigned char *key1;
  const unsigned char *key2;
  unsigned int key1bits;
  unsigned int key2bits;

  ret = mbedtls_aes_xts_decode_keys(key, keybits, &key1, &key1bits,
                                    &key2, &key2bits);
  if (ret != 0)
  {
    return ret;
  }

  /* Set the tweak key. Always set tweak key for encryption. */
  ret = mbedtls_aes_setkey_enc(&ctx->tweak, key2, key2bits);
  if (ret != 0)
  {
    return ret;
  }

  /* Set crypt key for decryption. */
  return mbedtls_aes_setkey_dec(&ctx->crypt, key1, key1bits);
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

/**
  * @brief AES key schedule (decryption)
  */
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
  return aes_set_key(ctx, key, keybits);
}

/**
  * @brief AES-ECB block encryption/decryption
  */
int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                          int mode,
                          const unsigned char input[16],
                          unsigned char output[16])
{
  int ret = 0;  /* return value */
  cmox_cipher_retval_t retval; /* STCryptoLib return value */

  if (ctx->ctx_init == 0U)  /* Context not initialize */
  {
    if (mode == MBEDTLS_AES_ENCRYPT)
    {
      ctx->cipher_ctx = cmox_ecb_construct(&ctx->ecb_ctx,
                                           CMOX_AES_ECB_ENC);
    }
    else
    {
      ctx->cipher_ctx = cmox_ecb_construct(&ctx->ecb_ctx,
                                           CMOX_AES_ECB_DEC);
    }

    retval = cmox_cipher_init(ctx->cipher_ctx);
    ret = aes_mbed_return_value(retval);
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      return ret;
    }

    /* Load key from mbed to cmox ctx */
    retval = cmox_cipher_setKey(ctx->cipher_ctx, ctx->aes_key,
                                ctx->aes_key_size);
    ret = aes_mbed_return_value(retval);
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      return ret;
    }
    ctx->ctx_init = 1; /* Set init indicator */
  }

  /* Do the encrypt/decrypt */
  retval = cmox_cipher_append(ctx->cipher_ctx, input, 16, output, NULL);
  ret = aes_mbed_return_value(retval);

  return ret;
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/**
  * @brief AES-CBC buffer encryption/decryption
  */
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx, int mode, size_t length,
                          unsigned char iv[16], const unsigned char *input,
                          unsigned char *output)
{
  cmox_cipher_retval_t retval; /*STCryptoLib return value */

  if ((length % 16U) != 0U)
  {
    return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
  }

  if (ctx->ctx_init == 0U)  /* Context not initialize */
  {
    if (mode == MBEDTLS_AES_ENCRYPT)
    {
      ctx->cipher_ctx = cmox_cbc_construct(&ctx->cbc_ctx,
                                           CMOX_AES_CBC_ENC);
    }
    else
    {
      ctx->cipher_ctx = cmox_cbc_construct(&ctx->cbc_ctx,
                                           CMOX_AES_CBC_DEC);
    }

    retval = cmox_cipher_init(ctx->cipher_ctx);
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    /* Load key from mbed to cmox ctx */
    retval = cmox_cipher_setKey(ctx->cipher_ctx, ctx->aes_key,
                                ctx->aes_key_size);
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    retval = cmox_cipher_setIV(ctx->cipher_ctx, iv, 16);
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    ctx->ctx_init = 1; /* Set init indicator */
  }

  /* Do the encrypt/decrypt */
  retval = cmox_cipher_append(ctx->cipher_ctx, input, length, output, NULL);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
  }

  return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_XTS)

/* Endianness with 64 bits values */
#ifndef GET_UINT64_LE
#define GET_UINT64_LE(n,b,i)                              \
  {                                                       \
    (n) = ( (uint64_t) (b)[(i) + 7] << 56 )               \
          | ( (uint64_t) (b)[(i) + 6] << 48 )             \
          | ( (uint64_t) (b)[(i) + 5] << 40 )             \
          | ( (uint64_t) (b)[(i) + 4] << 32 )             \
          | ( (uint64_t) (b)[(i) + 3] << 24 )             \
          | ( (uint64_t) (b)[(i) + 2] << 16 )             \
          | ( (uint64_t) (b)[(i) + 1] <<  8 )             \
          | ( (uint64_t) (b)[(i)    ]       );            \
  }
#endif /* !GET_UINT64_LE */

#ifndef PUT_UINT64_LE
#define PUT_UINT64_LE(n,b,i)                            \
  {                                                     \
    (b)[(i) + 7] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
  }
#endif /* !PUT_UINT64_LE */

/** @cond DOXYGEN_SHOULD_SKIP_THIS */
/**
  * @brief GF(2^128) multiplication function
  * @details
  * This function multiplies a field element by x in the polynomial field
  * representation. It uses 64-bit word operations to gain speed but compensates
  * for machine endianness and hence works correctly on both big and little
  * endian machines.
  */
static void mbedtls_gf128mul_x_ble(unsigned char r[16],
                                   const unsigned char x[16])
{
  uint64_t a = 0;
  uint64_t b = 0;
  uint64_t ra = 0;
  uint64_t rb = 0;

  GET_UINT64_LE(a, x, 0);
  GET_UINT64_LE(b, x, 8);

  ra = (a << 1)  ^ (0x0087ULL >> (8U - ((b >> 63) << 3)));
  rb = (a >> 63) | (b << 1);

  PUT_UINT64_LE(ra, r, 0);
  PUT_UINT64_LE(rb, r, 8);
}
/** @endcond */

/**
  * @brief AES-XTS buffer encryption/decryption
  */
int mbedtls_aes_crypt_xts(mbedtls_aes_xts_context *ctx,
                          int mode,
                          size_t length,
                          const unsigned char data_unit[16],
                          const unsigned char *input,
                          unsigned char *output)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  size_t blocks = length / 16U;
  size_t leftover = length % 16U;
  unsigned char tweak[16] = {0};
  unsigned char prev_tweak[16] = {0};
  unsigned char tmp[16] = {0};

  /* Data units must be at least 16 bytes long. */
  if (length < 16U)
  {
    return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
  }

  /* NIST SP 800-38E disallows data units larger than 2**20 blocks. */
  if (length > ((1UL << 20) * 16U))
  {
    return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
  }

  /* Compute the tweak. */
  ret = mbedtls_aes_crypt_ecb(&ctx->tweak, MBEDTLS_AES_ENCRYPT,
                              data_unit, tweak);
  if (ret != 0)
  {
    return ret;
  }

  while (blocks > 0U)
  {
    blocks--;
    size_t i = 0;

    if ((leftover != 0U) && (mode == MBEDTLS_AES_DECRYPT) && (blocks == 0U))
    {
      /* We are on the last block in a decrypt operation that has
       * leftover bytes, so we need to use the next tweak for this block,
       * and this tweak for the leftover bytes. Save the current tweak for
       * the leftovers and then update the current tweak for use on this,
       * the last full block. */
      (void) memcpy(prev_tweak, tweak, sizeof(tweak));
      mbedtls_gf128mul_x_ble(tweak, tweak);
    }

    for (i = 0; i < 16U; i++)
    {
      tmp[i] = input[i] ^ tweak[i];
    }

    ret = mbedtls_aes_crypt_ecb(&ctx->crypt, mode, tmp, tmp);
    if (ret != 0)
    {
      return ret;
    }

    for (i = 0; i < 16U; i++)
    {
      output[i] = tmp[i] ^ tweak[i];
    }

    /* Update the tweak for the next block. */
    mbedtls_gf128mul_x_ble(tweak, tweak);

    output += 16;
    input += 16;
  }

  if (leftover != 0U)
  {
    /* If we are on the leftover bytes in a decrypt operation, we need to
     * use the previous tweak for these bytes (as saved in prev_tweak). */
    unsigned char *t = (mode == MBEDTLS_AES_DECRYPT) ? prev_tweak : tweak;

    /* We are now on the final part of the data unit, which doesn't divide
     * evenly by 16. It's time for ciphertext stealing. */
    size_t i = 0;
    unsigned char *prev_output = output - 16;

    /* Copy ciphertext bytes from the previous block to our output for each
     * byte of ciphertext we won't steal. At the same time, copy the
     * remainder of the input for this final round (since the loop bounds
     * are the same). */
    for (i = 0; i < leftover; i++)
    {
      output[i] = prev_output[i];
      tmp[i] = input[i] ^ t[i];
    }

    /* Copy ciphertext bytes from the previous block for input in this
     * round. */
    for (; i < 16U; i++)
    {
      tmp[i] = prev_output[i] ^ t[i];
    }

    ret = mbedtls_aes_crypt_ecb(&ctx->crypt, mode, tmp, tmp);
    if (ret != 0)
    {
      return ret;
    }

    /* Write the result back to the previous block, overriding the previous
     * output we copied. */
    for (i = 0; i < 16U; i++)
    {
      prev_output[i] = tmp[i] ^ t[i];
    }
  }

  return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/**
  * @brief AES-CFB128 buffer encryption/decryption
  */
int mbedtls_aes_crypt_cfb128(mbedtls_aes_context *ctx,
                             int mode,
                             size_t length,
                             size_t *iv_off,
                             unsigned char iv[16],
                             const unsigned char *input,
                             unsigned char *output)
{
  unsigned char c = 0;
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  size_t n = 0;

  n = *iv_off;

  if (mode == MBEDTLS_AES_DECRYPT)
  {
    while (length > 0U)
    {
      length--;
      if (n == 0U)
      {
        ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
        if (ret != 0)
        {
          return ret;
        }
      }

      c = *input;
      input++;
      *output = (unsigned char)(c ^ iv[n]);
      output++;
      iv[n] = (unsigned char) c;

      n = (n + 1U) & 0x0FU;
    }
  }
  else
  {
    while (length > 0U)
    {
      length--;
      if (n == 0U)
      {
        ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
        if (ret != 0)
        {
          return ret;
        }
      }

      iv[n] = (unsigned char)(iv[n] ^ *input);
      *output = iv[n];
      input++;
      output++;
      n = (n + 1U) & 0x0FU;
    }
  }

  *iv_off = n;

  return 0;
}

/**
  * @brief AES-CFB8 buffer encryption/decryption
  */
int mbedtls_aes_crypt_cfb8(mbedtls_aes_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char iv[16],
                           const unsigned char *input,
                           unsigned char *output)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  unsigned char c;
  unsigned char ov[17];

  while (length > 0U)
  {
    length--;
    (void) memcpy(ov, iv, 16);
    ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
    if (ret != 0)
    {
      return ret;
    }

    if (mode == MBEDTLS_AES_DECRYPT)
    {
      ov[16] = *input;
    }

    c  = (unsigned char)(iv[0] ^ *input);
    *output = c;
    output++;
    input++;

    if (mode == MBEDTLS_AES_ENCRYPT)
    {
      ov[16] = c;
    }

    (void) memcpy(iv, ov + 1, 16);
  }

  return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
/**
  * @brief AES-OFB (Output Feedback Mode) buffer encryption/decryption
  */
int mbedtls_aes_crypt_ofb(mbedtls_aes_context *ctx,
                          size_t length,
                          size_t *iv_off,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{
  int ret = 0;
  size_t n = 0;

  n = *iv_off;

  if (n > 15U)
  {
    return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
  }

  while (length > 0U)
  {
    length--;
    if (n == 0U)
    {
      ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
      if (ret != 0)
      {
        goto exit;
      }
    }
    *output =  *input ^ iv[n];
    output++;
    input++;

    n = (n + 1U) & 0x0FU;
  }

  *iv_off = n;

exit:
  return ret;
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/**
  * @brief AES-CTR buffer encryption/decryption
  */
int mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx,
                          size_t length,
                          size_t *nc_off,
                          unsigned char nonce_counter[16],
                          unsigned char stream_block[16],
                          const unsigned char *input,
                          unsigned char *output)
{
  unsigned char c = 0;
  int i = 0;
  size_t n = 0;

  /* Encrypt and decrypt are the same operation in CTR */
  n = *nc_off;

  while (length > 0U)
  {
    length--;
    if (n == 0U)
    {
      if (mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, nonce_counter,
                                stream_block) != 0)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }

      for (i = 16; i > 0; i--)
      {
        if (++nonce_counter[i - 1] != 0U)
        {
          break;
        }
      }
    }
    c = *input;
    input++;
    *output = (unsigned char)(c ^ stream_block[n]);
    output++;

    n = (n + 1U) & 0x0FU;
  }

  *nc_off = n;

  return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
  int ret = 0; /* return value */
  cmox_cipher_retval_t retval; /* STCryptoLib return value */

  /* Do the encrypt */
  retval = cmox_cipher_append(ctx->cipher_ctx, input, 16, output, NULL);
  ret = aes_mbed_return_value(retval);

  return ret;
}

int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
  int ret = 0; /* return value */
  cmox_cipher_retval_t retval; /* STCryptoLib return value */

  /* Do the decrypt */
  retval = cmox_cipher_append(ctx->cipher_ctx, input, 16, output, NULL);
  ret = aes_mbed_return_value(retval);

  return ret;
}

/**
  * @}
  */

#endif /* MBEDTLS_STCRYPTOLIB_AES_ALT */

#endif /* MBEDTLS_AES_ALT */
#endif /* MBEDTLS_AES_C */
