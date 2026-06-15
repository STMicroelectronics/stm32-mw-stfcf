/**
  ******************************************************************************
  * @file    cryp_gcm_alt.c
  * @brief   Implementation of mbedtls_alt GCM module
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
  * NIST SP800-38D compliant GCM implementation
  *
  * This file implements GCM based on STM32 CRYP hardware crypto accelerator.
  */

/* Includes ------------------------------------------------------------------*/
#include "mbedtls/gcm.h"
#if defined(MBEDTLS_GCM_C)
#if defined(MBEDTLS_GCM_ALT)
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_HAL_GCM_ALT)
#if ((defined(USE_HAL_CRYP_MODULE) && (USE_HAL_CRYP_MODULE == 1U)))

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define ST_GCM_TIMEOUT    0xFFU   /* 255 ms timeout for the crypto processor */
#define IV_LENGTH         12U     /* implementations restrict support to 96 bits */
#define HAL_CRYP_KEY_SIZE_192 192U /* AES key size 192 bit */
/* Private macro -------------------------------------------------------------*/
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
  do {                                                  \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
          | ( (uint32_t) (b)[(i) + 1U] << 16 )           \
          | ( (uint32_t) (b)[(i) + 2U] <<  8 )           \
          | ( (uint32_t) (b)[(i) + 3U]       );          \
  } while( 0 )
#endif /* !GET_UINT32_BE */

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
  do {                                                  \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
  } while( 0 )
#endif /* !PUT_UINT32_BE */

/* Private variables ---------------------------------------------------------*/
static hal_cryp_handle_t *pGCM = NULL; /* pointer referencing the CRYP handle */
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/*
 * Initialize a context
 */
void mbedtls_gcm_init(mbedtls_gcm_context *ctx)
{
  pGCM = mx_stfcf_mbedtls_alt_hal_cryp_gcm_gethandle();
  memset(ctx, 0, sizeof(mbedtls_gcm_context));
}

int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits)
{
  (void) cipher;
  int ret = 0;
  unsigned int i = 0;
  if (keybits == HAL_CRYP_KEY_SIZE_192)
  {
    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
  }

  /* Format and fill AES key  */
  for (i = 0; i < (keybits / 32U); i++)
  {
    GET_UINT32_BE(ctx->gcm_key[i], key, 4U * i);
  }
  ctx->Keysize = keybits;

  return ret;
}

int mbedtls_gcm_starts(mbedtls_gcm_context *ctx,
                       int mode,
                       const unsigned char *iv, size_t iv_len)
{
  size_t i = 0;
  uint32_t *iv_p = (uint32_t *)(ctx->y);

  /* IV is limited to 2^64 bits, so 2^61 bytes */
  /* IV is not allowed to be zero length */
  if ((iv_len == 0U) || ((((uint64_t) iv_len) >> 61) != 0U))
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  (void) memset(ctx->y, 0x00, sizeof(ctx->y));
  (void) memset(ctx->buf, 0x00, sizeof(ctx->buf));

  /* HW implementation restrict support to the length of 96 bits */
  if (IV_LENGTH != iv_len)
  {
    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
  }

  ctx->mode = mode;
  ctx->len = 0;

  /* Set IV with invert endianness */
  for (i = 0; i < (iv_len / 4U); i++)
  {
    GET_UINT32_BE(iv_p[i], iv, 4U * i);
  }

  /* counter value must be set to 2 when processing the first block of payload */
  iv_p[3] = 0x00000002;
  ctx->p_gcm_config.p_init_vect = (uint32_t *)ctx->y;

  return 0;
}

/**
  * mbedtls_gcm_context::buf contains the partial state of the computation of
  * the authentication tag.
  * mbedtls_gcm_context::add_len and mbedtls_gcm_context::len indicate
  * different stages of the computation:
  *     * len == 0 && add_len == 0:      initial state
  *     * len == 0 && add_len % 16 != 0: the first `add_len % 16` bytes have
  *                                      a partial block of AD that has been
  *                                      xored in but not yet multiplied in.
  *     * len == 0 && add_len % 16 == 0: the authentication tag is correct if
  *                                      the data ends now.
  *     * len % 16 != 0:                 the first `len % 16` bytes have
  *                                      a partial block of ciphertext that has
  *                                      been xored in but not yet multiplied in.
  *     * len > 0 && len % 16 == 0:      the authentication tag is correct if
  *                                      the data ends now.
  */
int mbedtls_gcm_update_ad(mbedtls_gcm_context *ctx,
                          const unsigned char *add, size_t add_len)
{
  /* additional authentication data is limited to 2^64 bits, so 2^61 bytes */
  if (((uint64_t) add_len >> 61) != 0U)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  if (add_len != 0U)
  {
    ctx->p_gcm_config.p_header = (uint32_t *)add;
    /* header buffer in byte length */
    ctx->p_gcm_config.header_size_byte = (uint32_t)add_len;
  }
  else
  {
    ctx->p_gcm_config.p_header = NULL;
    ctx->p_gcm_config.header_size_byte = 0;
  }
  if (HAL_CRYP_AES_GCM_GMAC_SetConfig(pGCM, &ctx->p_gcm_config) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }
  switch (ctx->Keysize)
  {

    case 128:
      if (HAL_CRYP_AES_SetNormalKey(pGCM, HAL_CRYP_KEY_SIZE_128BIT, ctx->gcm_key) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
      break;

    case 256:
      if (HAL_CRYP_AES_SetNormalKey(pGCM, HAL_CRYP_KEY_SIZE_256BIT, ctx->gcm_key) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
      break;

    default :
      return  MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  if (HAL_CRYP_SetDataSwapping(pGCM, HAL_CRYP_DATA_SWAPPING_BYTE) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  return 0;
}

int mbedtls_gcm_update(mbedtls_gcm_context *ctx,
                       const unsigned char *input, size_t input_length,
                       unsigned char *output, size_t output_size,
                       size_t *output_length)
{
  (void) output_size;
  uint16_t wordnb = 0;          /* number of four data words */
  uint16_t wordlen = 0;         /* length (in bytes) of four data words */
  uint16_t in_datalen = 0;  /* length (in bytes) of processed data within input buffer */
  __ALIGN_BEGIN unsigned char work_buf[16] __ALIGN_END;
  uint16_t work_buf_len = 0;

  if ((output > input) && ((size_t)(output - input) < input_length))
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  /* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
   * Also check for possible overflow */
  if (((ctx->len + input_length) < ctx->len)
      || (((uint64_t) ctx->len + input_length) > 0xFFFFFFFE0ULL))
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  /* Calculate number of four data words */
  wordnb = input_length / 16U;

  /* if available, process them */
  if (wordnb)
  {
    /* Convert in bytes */
    wordlen = wordnb * 16U;

    if (ctx->mode == MBEDTLS_GCM_DECRYPT)
    {
      if (HAL_CRYP_Decrypt(pGCM,
                           (const uint32_t *)input,
                           wordlen,
                           (uint32_t *)output,
                           ST_GCM_TIMEOUT) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
    }
    else
    {
      if (HAL_CRYP_Encrypt(pGCM,
                           (const uint32_t *)input,
                           wordlen,
                           (uint32_t *)output,
                           ST_GCM_TIMEOUT) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }
    }

    /* update total length */
    ctx->len += wordlen;

    in_datalen += wordlen;

    if (in_datalen < input_length)
    {
      /* Process them into a last four data word */
      goto last_data_word;
    }
    else
    {
      goto exit;
    }
  }

last_data_word:
  /* Calculate remaining bytes */
  /* Can have a null length when payload is omitted (GMAC) */
  work_buf_len = (uint16_t)((input_length - in_datalen) % 16U);

  (void) memset(work_buf, 0, sizeof(work_buf));
  (void) memcpy(work_buf, input + in_datalen, work_buf_len);

  if (ctx->mode == MBEDTLS_GCM_DECRYPT)
  {
    if (HAL_CRYP_Decrypt(pGCM,
                         (uint32_t *)work_buf,
                         work_buf_len,
                         (uint32_t *)(output + in_datalen),
                         ST_GCM_TIMEOUT) != HAL_OK)
    {
      return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
  }
  else
  {
    if (HAL_CRYP_Encrypt(pGCM,
                         (uint32_t *)work_buf,
                         work_buf_len,
                         (uint32_t *)(output + in_datalen),
                         ST_GCM_TIMEOUT) != HAL_OK)
    {
      return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
  }

  /* update total length */
  ctx->len += work_buf_len;

exit:

  *output_length = input_length;
  return 0;
}

int mbedtls_gcm_finish(mbedtls_gcm_context *ctx,
                       unsigned char *output, size_t output_size,
                       size_t *output_length,
                       unsigned char *tag, size_t tag_len)
{
  (void) output;
  (void) output_size;
  (void) output_length;
  __ALIGN_BEGIN uint8_t mac[16]      __ALIGN_END; /* temporary mac */

  if ((tag_len > 16U) || (tag_len < 4U))
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  /* implementation restrict support to a 16 bytes tag buffer */
  if (tag_len != 16U)
  {
    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
  }

  /* Tag has a variable length */
  (void) memset(mac, 0, sizeof(mac));

  /* Generate the authentication TAG */
  if (HAL_CRYP_GCM_GenerateAuthTAG(pGCM,
                                   (uint32_t *)mac,
                                   ST_GCM_TIMEOUT) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  (void) memcpy(tag, mac, tag_len);

  mbedtls_platform_zeroize(ctx->gcm_key, sizeof(ctx->gcm_key));
  return 0;
}

int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx,
                              int mode,
                              size_t length,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *add,
                              size_t add_len,
                              const unsigned char *input,
                              unsigned char *output,
                              size_t tag_len,
                              unsigned char *tag)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  size_t olen = 0;

  ret = mbedtls_gcm_starts(ctx, mode, iv, iv_len);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_gcm_update_ad(ctx, add, add_len);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_gcm_update(ctx, input, length,
                           output, length, &olen);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_gcm_finish(ctx, NULL, 0, &olen, tag, tag_len);
  if (ret != 0)
  {
    return ret;
  }

  return 0;
}

int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx,
                             size_t length,
                             const unsigned char *iv,
                             size_t iv_len,
                             const unsigned char *add,
                             size_t add_len,
                             const unsigned char *tag,
                             size_t tag_len,
                             const unsigned char *input,
                             unsigned char *output)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  unsigned char check_tag[16] = {0};
  size_t i = 0;
  unsigned char diff = 0;

  ret = mbedtls_gcm_crypt_and_tag(ctx, MBEDTLS_GCM_DECRYPT, length,
                                  iv, iv_len, add, add_len,
                                  input, output, tag_len, check_tag);
  if (ret != 0)
  {
    return ret;
  }

  /* Check tag in "constant-time" */
  diff = 0;
  for (i = 0; i < tag_len; i++)
  {
    diff |= tag[i] ^ check_tag[i];
  }

  if (diff != 0U)
  {
    mbedtls_platform_zeroize(output, length);
    return MBEDTLS_ERR_GCM_AUTH_FAILED;
  }

  return 0;
}

void mbedtls_gcm_free(mbedtls_gcm_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }

  mbedtls_platform_zeroize(ctx, sizeof(mbedtls_gcm_context));
}

#endif /* MBEDTLS_HAL_GCM_ALT */
#endif /* USE_HAL_CRYP_MODULE*/
#endif /* MBEDTLS_GCM_ALT */
#endif /* MBEDTLS_GCM_C */
