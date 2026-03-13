/**
  ******************************************************************************
  * @file    cryp_aes_alt.c
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
  * This file implements AES block cipher based on STM32 CRYP hardware crypto
  * accelerator.
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

#if defined(MBEDTLS_HAL_AES_ALT)
#if ((defined(USE_HAL_CRYP_MODULE) && (USE_HAL_CRYP_MODULE == 1U)))

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define ST_CRYP_TIMEOUT     0xFFU   /* 255 ms timeout for the crypto processor */
#define ST_CRYP_NO_ALGO     0xFFFFU /* any algo is programmed */
#define HAL_CRYP_KEY_SIZE_192 192U /* AES key size 192 bit */
/* Private macro -------------------------------------------------------------*/
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
  do {                                                  \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
          | ( (uint32_t) (b)[(i) + 1U] << 16 )          \
          | ( (uint32_t) (b)[(i) + 2U] <<  8 )          \
          | ( (uint32_t) (b)[(i) + 3U]       );         \
  } while( 0 )
#endif /* GET_UINT32_BE */

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
  do {                                                    \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
  } while( 0 )
#endif /* PUT_UINT32_BE */

/* Private variables ---------------------------------------------------------*/
static hal_cryp_handle_t *pCRYP = NULL;  /* pointer referencing the CRYP handle from the generated code */
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

static int aes_set_key(mbedtls_aes_context *ctx,
                       const unsigned char *key,
                       unsigned int keybits)
{

  uint32_t i = 0;

  if (keybits == HAL_CRYP_KEY_SIZE_192)
  {
    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
  }
  /* Format and fill AES key  */
  for (i = 0; i < (keybits / 32U); i++)
  {
    GET_UINT32_BE(ctx->aes_key[i], key, (4U * i));
  }
  ctx->Keysize = keybits;
  return 0;
}

/* Implementation that must never be optimized out by the compiler */
static void mbedtls_zeroize(void *value, size_t size)
{
  volatile unsigned char *p = (unsigned char *)value;
  size_t n = size;
  while (n > 0U)
  {
    *p = 0;
    p++;
    n--;
  }
}

void mbedtls_aes_init(mbedtls_aes_context *ctx)
{
  /* Get the AES handle */
  pCRYP = mx_stfcf_mbedtls_alt_hal_cryp_gethandle();

  (void) memset(ctx, 0, sizeof(mbedtls_aes_context));
  ctx->Algorithm = ST_CRYP_NO_ALGO;
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

/*
 * AES key schedule (encryption)
 */
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
  return aes_set_key(ctx, key, keybits);
}

/*
 * AES key schedule (decryption)
 */
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
  return aes_set_key(ctx, key, keybits);
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
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
  }

  *key1bits = half_keybits;
  *key2bits = half_keybits;
  *key1 = &key[0];
  *key2 = &key[half_keybytes];

  return 0;
}

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

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                          int mode,
                          const unsigned char input[16],
                          unsigned char output[16])
{
  int ret = 0;
  /* Configure the CRYP  */
  if (HAL_CRYP_AES_ECB_SetConfig(pCRYP) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  switch (ctx->Keysize)
  {

    case 128:
      if (HAL_CRYP_AES_SetNormalKey(pCRYP, HAL_CRYP_KEY_SIZE_128BIT, ctx->aes_key) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
      break;

    case 256:
      if (HAL_CRYP_AES_SetNormalKey(pCRYP, HAL_CRYP_KEY_SIZE_256BIT, ctx->aes_key) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
      break;

    default:
      return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
  }

  if (HAL_CRYP_SetDataSwapping(pCRYP, HAL_CRYP_DATA_SWAPPING_BYTE) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  if (mode == MBEDTLS_AES_DECRYPT)   /* AES decryption */
  {
    ret = mbedtls_internal_aes_decrypt(ctx, input, output);
    if (ret != 0)
    {
      return ret;
    }
  }
  else /* AES encryption */
  {
    ret = mbedtls_internal_aes_encrypt(ctx, input, output);
    if (ret != 0)
    {
      return ret;
    }
  }

  return 0;
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)

int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{


  __ALIGN_BEGIN static uint32_t iv_32B[4] __ALIGN_END;

  if (length % 16)
  {
    return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
  }


  /* Set IV with invert endianness */
  GET_UINT32_BE(iv_32B[0], iv, 0U);
  GET_UINT32_BE(iv_32B[1], iv, 4U);
  GET_UINT32_BE(iv_32B[2], iv, 8U);
  GET_UINT32_BE(iv_32B[3], iv, 12U);

  if (HAL_CRYP_AES_CBC_SetConfig(pCRYP, iv_32B) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }
  switch (ctx->Keysize)
  {
    case 128:
      if (HAL_CRYP_AES_SetNormalKey(pCRYP, HAL_CRYP_KEY_SIZE_128BIT, ctx->aes_key) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
      break;

    case 256:
      if (HAL_CRYP_AES_SetNormalKey(pCRYP, HAL_CRYP_KEY_SIZE_256BIT, ctx->aes_key) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
      break;

    default:
      return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
  }

  if (HAL_CRYP_SetDataSwapping(pCRYP, HAL_CRYP_DATA_SWAPPING_BYTE) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  if (mode == MBEDTLS_AES_DECRYPT)
  {
    (void) memcpy(iv, &input[length - 16U], 16);
    if (HAL_CRYP_Decrypt(pCRYP,
                         (const uint32_t *)input,
                         (uint16_t)length,
                         (uint32_t *)output,
                         ST_CRYP_TIMEOUT) != HAL_OK)
    {
      return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
  }
  else
  {
    if (HAL_CRYP_Encrypt(pCRYP,
                         (const uint32_t *)input,
                         (uint16_t)length,
                         (uint32_t *)output,
                         ST_CRYP_TIMEOUT) != HAL_OK)
    {
      return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    /* current output is the IV vector for the next call */
    (void) memcpy(iv, &output[length - 16U], 16);
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

/*
 * GF(2^128) multiplication function
 *
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

  ra = (a << 1) ^ ((uint64_t)0x0087U >> (8U - ((b >> 63) << 3)));
  rb = (a >> 63) | (b << 1);

  PUT_UINT64_LE(ra, r, 0);
  PUT_UINT64_LE(rb, r, 8);
}

/*
 * AES-XTS buffer encryption/decryption
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
/*
 * AES-CFB128 buffer encryption/decryption
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

      c = (unsigned char)(iv[n] ^ *input);
      input++;
      *output = c;
      output++;
      iv[n] = c;

      n = (n + 1U) & 0x0FU;
    }
  }

  *iv_off = n;

  return 0;
}

/*
 * AES-CFB8 buffer encryption/decryption
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

    c = (unsigned char)(iv[0] ^ *input);
    input++;
    *output = c;
    output++;

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
/*
 * AES-OFB (Output Feedback Mode) buffer encryption/decryption
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
/*
 * AES-CTR buffer encryption/decryption
 */
int mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx,
                          size_t length,
                          size_t *nc_off,
                          unsigned char nonce_counter[16],
                          unsigned char stream_block[16],
                          const unsigned char *input,
                          unsigned char *output)
{
  size_t in_length = 0;
  size_t last_bytes = 0;
  __ALIGN_BEGIN static uint32_t iv_32B[4] __ALIGN_END;
  __ALIGN_BEGIN unsigned char work_buf[16] __ALIGN_END;

  last_bytes = length % 16U;
  in_length = length - last_bytes;

  /* Set IV with invert endianness */
  GET_UINT32_BE(iv_32B[0], nonce_counter, 0U);
  GET_UINT32_BE(iv_32B[1], nonce_counter, 4U);
  GET_UINT32_BE(iv_32B[2], nonce_counter, 8U);
  GET_UINT32_BE(iv_32B[3], nonce_counter, 12U);

  /* Set AES configuration */
  if (HAL_CRYP_AES_CTR_SetConfig(pCRYP, iv_32B) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  switch (ctx->Keysize)
  {
    case 128:
      if (HAL_CRYP_AES_SetNormalKey(pCRYP, HAL_CRYP_KEY_SIZE_128BIT, ctx->aes_key) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
      break;

    case 256:
      if (HAL_CRYP_AES_SetNormalKey(pCRYP, HAL_CRYP_KEY_SIZE_256BIT, ctx->aes_key) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
      break;

    default:
      return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
  }

  if (HAL_CRYP_SetDataSwapping(pCRYP, HAL_CRYP_DATA_SWAPPING_BYTE) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  if (HAL_CRYP_Encrypt(pCRYP, (uint32_t *)input, (uint16_t)in_length, (uint32_t *)output, ST_CRYP_TIMEOUT) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  if (last_bytes)
  {
    (void) memset(work_buf, 0, sizeof(work_buf));
    (void) memcpy(work_buf, input + in_length, last_bytes);
    if (HAL_CRYP_Decrypt(pCRYP, (uint32_t *)work_buf, 16U, (uint32_t *)(output + in_length),
                         ST_CRYP_TIMEOUT) != HAL_OK)
    {
      return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
  }

  return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
  if (HAL_CRYP_Encrypt(pCRYP, (const uint32_t *)input, 16, (uint32_t *)output, ST_CRYP_TIMEOUT) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }
  return 0;

}

int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
  if (HAL_CRYP_Decrypt(pCRYP, (const uint32_t *)input, 16, (uint32_t *)output, ST_CRYP_TIMEOUT) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }
  return 0;
}

#endif /* MBEDTLS_HAL_AES_ALT */
#endif /* USE_HAL_CRYP_MODULE*/
#endif /* MBEDTLS_AES_ALT */
#endif /* MBEDTLS_AES_C */
