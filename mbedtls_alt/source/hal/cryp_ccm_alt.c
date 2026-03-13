/**
  ******************************************************************************
  * @file    cryp_ccm_alt.c
  * @brief   Implementation of mbedtls_alt Middleware CCM module
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
  *  This file implements ST CCM HW services based on API from mbed TLS
  *
  * Definition of CCM:
  * http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
  * RFC 3610 "Counter with CBC-MAC (CCM)"
  *
  * Related:
  * RFC 5116 "An Interface and Algorithms for Authenticated Encryption"
  */

/* Includes ------------------------------------------------------------------*/
#include "common.h"

#if defined(MBEDTLS_CCM_C)
#if defined(MBEDTLS_CCM_ALT)

#include "mbedtls/ccm.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/constant_time.h"

#include <string.h>
#include "mbedtls/platform.h"

#if defined(MBEDTLS_HAL_AES_ALT)
#if ((defined(USE_HAL_CRYP_MODULE) && (USE_HAL_CRYP_MODULE == 1U)))

/* Parameter validation macros */
/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define ST_CRYP_TIMEOUT   1000  /* timeout (in ms) for the crypto processor   */

#define H_LENGTH 2U /*!< Formatting of the Associated Data
                        If 0 < a < 2e16-2e8,
                        then a is encoded as [a]16, i.e., two octets */
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

/* Private variables ---------------------------------------------------------*/
static hal_cryp_handle_t *pCCM = NULL; /* pointer referencing the CRYP handle */
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/
/*
 * initializes the specified CCM context
 */
void mbedtls_ccm_init(mbedtls_ccm_context *ctx)
{
  pCCM = mx_stfcf_mbedtls_alt_hal_cryp_ccm_gethandle();
  (void) memset((void *)ctx, 0, sizeof(mbedtls_ccm_context));
}

/*
 * Set the CCM key and key size
 */
int mbedtls_ccm_setkey(mbedtls_ccm_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits)
{
  uint32_t  i;
  int ret = 0;
  if (keybits == HAL_CRYP_KEY_SIZE_192)
  {
    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
  }
  /* Format and fill AES key  */
  for (i = 0; i < (keybits / 32U); i++)
  {
    GET_UINT32_BE(ctx->ccm_key[i], key, 4U * i);
  }
  /* Store the keybits in the context */
  ctx->Keysize = keybits;

  return (ret);
}

/*
 * Free context
 */
void mbedtls_ccm_free(mbedtls_ccm_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }

  mbedtls_platform_zeroize(ctx, sizeof(mbedtls_ccm_context));
}

#define CCM_STATE__CLEAR                0
#define CCM_STATE__STARTED              (1U << 0)
#define CCM_STATE__LENGTHS_SET          (1U << 1)
#define CCM_STATE__AUTH_DATA_STARTED    (1U << 2)
#define CCM_STATE__AUTH_DATA_FINISHED   (1U << 3)
#define CCM_STATE__ERROR                (1U << 4)

/*
 * Clears the CCM state and zeroizes the first block (B0) buffer.
 * It is called at the end of CCM operation or when an error occurs.
 */
static void mbedtls_ccm_clear_state(mbedtls_ccm_context *ctx)
{
  ctx->state = CCM_STATE__CLEAR;
  (void) memset(ctx->y, 0, 16);
}

/*
 * Starts a CCM encryption or decryption operation.
 */
static int ccm_calculate_first_block_if_ready(mbedtls_ccm_context *ctx)
{
  uint32_t i = 0;
  size_t len_left = 0;
  uint32_t *iv_p = (uint32_t *)(ctx->y);

  /* length calculation can be done only after both
   * mbedtls_ccm_starts() and mbedtls_ccm_set_lengths() have been executed
   */
  if (((ctx->state & CCM_STATE__STARTED) == 0U) || ((ctx->state & CCM_STATE__LENGTHS_SET) == 0U))
  {
    return 0;
  }

  /* CCM expects non-empty tag.
   * CCM* allows empty tag. For CCM* without tag, ignore plaintext length.
   */
  if (ctx->tag_len == 0U)
  {
    if ((ctx->mode == MBEDTLS_CCM_STAR_ENCRYPT) || (ctx->mode == MBEDTLS_CCM_STAR_DECRYPT))
    {
      ctx->plaintext_len = 0;
    }
    else
    {
      return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
  }

  /*
   * First block:
   * 0        .. 0        flags
   * 1        .. iv_len   nonce (aka iv)  - set by: mbedtls_ccm_starts()
   * iv_len+1 .. 15       length
   *
   * With flags as (bits):
   * 7        0
   * 6        add present?
   * 5 .. 3   (t - 2) / 2
   * 2 .. 0   q - 1
   */
  ctx->y[0] |= (uint8_t)(((ctx->add_len > 0U) ? 1U : 0U) << 6);
  ctx->y[0] |= (uint8_t)(((ctx->tag_len - 2U) / 2U) << 3);
  ctx->y[0] |= (uint8_t)(ctx->q - 1U);

  len_left = ctx->plaintext_len;
  for (i = 0; i < ctx->q; i++)
  {
    ctx->y[15U - i] = MBEDTLS_BYTE_0(len_left);
    len_left >>= 8;
  }

  if (len_left > 0U)
  {
    ctx->state |= CCM_STATE__ERROR;
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  /* first authentication block */
  for (i = 0; i < 4U; i++)
  {
    GET_UINT32_BE(iv_p[i], ctx->y, 4U * i);
  }
  /* get the first authentication block */
  ctx->p_ccm_config.p_b0 = (uint32_t *)ctx->y;

  return 0;
}

/* This function starts a CCM encryption or decryption operation */
int mbedtls_ccm_starts(mbedtls_ccm_context *ctx,
                       int mode,
                       const unsigned char *iv,
                       size_t iv_len)
{
  /* Also implies q is within bounds */
  if ((iv_len < 7U) || (iv_len > 13U))
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  ctx->mode = mode;
  ctx->q = 16U - 1U - iv_len;

  /*
   * See ccm_calculate_first_block_if_ready() for block layout description
   */
  (void) memcpy(ctx->y + 1, iv, iv_len);

  ctx->state |= CCM_STATE__STARTED;
  return ccm_calculate_first_block_if_ready(ctx);
}

/*
 * Feeds an input buffer as associated data in a CCM encryption or decryption operation.
 */
int mbedtls_ccm_set_lengths(mbedtls_ccm_context *ctx,
                            size_t total_ad_len,
                            size_t plaintext_len,
                            size_t tag_len)
{
  /*
   * Check length requirements: SP800-38C A.1
   * Additional requirement: a < 2^16 - 2^8 to simplify the code.
   * 'length' checked later (when writing it to the first block)
   *
   * Also, loosen the requirements to enable support for CCM* (IEEE 802.15.4).
   */
  if ((tag_len == 2U) || (tag_len > 16U) || ((tag_len % 2U) != 0U))
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  if (total_ad_len >= 0xFF00U)
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  ctx->plaintext_len = plaintext_len;
  ctx->add_len = total_ad_len;
  ctx->tag_len = tag_len;

  ctx->state |= CCM_STATE__LENGTHS_SET;
  return ccm_calculate_first_block_if_ready(ctx);
}

/* Feeds an input buffer as associated data in a CCM encryption or decryption operation. */
int mbedtls_ccm_update_ad(mbedtls_ccm_context *ctx,
                          const unsigned char *add,
                          size_t add_len)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  unsigned char *b1_padded_addr = NULL;            /* Formatting of B1   */
  size_t b1_length = 0;                            /* B1 with padding    */
  unsigned int b1_padding = 0;                     /* B1 word alignment  */

  if ((ctx->state & CCM_STATE__ERROR) != 0U)
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  if (add_len > 0U)
  {
    if ((ctx->state & CCM_STATE__AUTH_DATA_FINISHED) != 0U)
    {
      return MBEDTLS_ERR_CCM_BAD_INPUT;
    }

    if (!((ctx->state & CCM_STATE__AUTH_DATA_STARTED) != 0U))
    {
      if (add_len > ctx->add_len)
      {
        return MBEDTLS_ERR_CCM_BAD_INPUT;
      }

      /* Extra bytes to deal with data padding such that
       * the resulting string can be partitioned into words
       */
      b1_padding = ((add_len + H_LENGTH) % 4U);
      b1_length = add_len + H_LENGTH + b1_padding;

      b1_padded_addr = mbedtls_calloc(1, b1_length);

      if (b1_padded_addr == NULL)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }

      /* Header length */
      b1_padded_addr[0] = (unsigned char)((add_len >> 8) & 0xFFU);
      b1_padded_addr[1] = (unsigned char)((add_len) & 0xFFU);

      /* data concatenation */
      (void) memcpy(b1_padded_addr + H_LENGTH, add, add_len);

      /* blocks (B) associated to the Associated Data (A) */
      ctx->p_ccm_config.p_header = (uint32_t *)b1_padded_addr;
      ctx->p_ccm_config.header_size_byte = b1_length;

      /* Configure the CRYP with the CCM algorithm */
      if (HAL_CRYP_AES_CCM_SetConfig(pCCM, &ctx->p_ccm_config) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }

      /* Configure the CRYP Normal key */
      switch (ctx->Keysize)
      {
        case 128:
          if (HAL_CRYP_AES_SetNormalKey(pCCM, HAL_CRYP_KEY_SIZE_128BIT, ctx->ccm_key) != HAL_OK)
          {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
          }
          break;

        case 256:
          if (HAL_CRYP_AES_SetNormalKey(pCCM, HAL_CRYP_KEY_SIZE_256BIT, ctx->ccm_key) != HAL_OK)
          {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
          }
          break;

        default:
          return MBEDTLS_ERR_CCM_BAD_INPUT;
      }

      /* Configure the CRYP data swapping */
      if (HAL_CRYP_SetDataSwapping(pCCM, HAL_CRYP_DATA_SWAPPING_BYTE) != HAL_OK)
      {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      }

      ctx->state |= CCM_STATE__AUTH_DATA_STARTED;


      if ((ctx->mode == MBEDTLS_CCM_ENCRYPT)
          || (ctx->mode == MBEDTLS_CCM_STAR_ENCRYPT))
      {
        /* Encrypt user data in polling mode */
        if (HAL_CRYP_Encrypt(pCCM,
                             (uint32_t *)NULL,
                             0,
                             (uint32_t *)NULL,
                             ST_CRYP_TIMEOUT) != HAL_OK)
        {
          ctx->state |= CCM_STATE__ERROR;
          ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
          goto exit;
        }
      }

      if ((ctx->mode == MBEDTLS_CCM_DECRYPT)
          || (ctx->mode == MBEDTLS_CCM_STAR_DECRYPT))
      {
        /* Decrypt user data in polling mode. */
        if (HAL_CRYP_Decrypt(pCCM,
                             (uint32_t *)NULL,
                             0,
                             (uint32_t *)NULL,
                             ST_CRYP_TIMEOUT) != HAL_OK)
        {
          ctx->state |= CCM_STATE__ERROR;
          ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
          goto exit;
        }
      }

    }
  }
  else
  {
    ctx->p_ccm_config.p_header = NULL;
    ctx->p_ccm_config.header_size_byte = 0;
  }

  ctx->state |= CCM_STATE__AUTH_DATA_FINISHED;
  ret = 0;

exit:
  if (add_len > 0U)
  {
    mbedtls_free(b1_padded_addr);
  }
  return ret;
}

/* feeds an input buffer into an ongoing CCM encryption or decryption operation. */
int mbedtls_ccm_update(mbedtls_ccm_context *ctx,
                       const unsigned char *input, size_t input_len,
                       unsigned char *output, size_t output_size,
                       size_t *output_len)
{
  if ((ctx->state & CCM_STATE__ERROR) != 0U)
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  /* Check against plaintext length only if performing operation with
   * authentication
   */
  if ((ctx->tag_len != 0U) && (input_len > ctx->plaintext_len))
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  if (output_size < input_len)
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  *output_len = input_len;

  pCCM->data_size_sum_byte = 12U;

  /* blocks (B) associated to the plaintext message (P) */
  if ((ctx->mode == MBEDTLS_CCM_ENCRYPT) || (ctx->mode == MBEDTLS_CCM_STAR_ENCRYPT))
  {
    /* Encrypt user data in polling mode */
    if (HAL_CRYP_Encrypt(pCCM,
                         (const uint32_t *)input,
                         (uint16_t)input_len,
                         (uint32_t *)output,
                         ST_CRYP_TIMEOUT) != HAL_OK)
    {
      ctx->state |= CCM_STATE__ERROR;
      return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
  }

  if ((ctx->mode == MBEDTLS_CCM_DECRYPT)
      || (ctx->mode == MBEDTLS_CCM_STAR_DECRYPT))
  {
    /* Decrypt user data in polling mode. */
    if (HAL_CRYP_Decrypt(pCCM,
                         (const uint32_t *)input,
                         (uint16_t)input_len,
                         (uint32_t *)output,
                         ST_CRYP_TIMEOUT) != HAL_OK)
    {
      ctx->state |= CCM_STATE__ERROR;
      return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
  }


  return 0;
}

/* This function finishes the CCM operation and generates the authentication tag. */
int mbedtls_ccm_finish(mbedtls_ccm_context *ctx, unsigned char *output, size_t output_size, size_t *ciphertext_length,
                       unsigned char *tag, size_t tag_len)
{
  __ALIGN_BEGIN uint8_t mac[16]      __ALIGN_END;  /* temporary mac */

  if ((ctx->state & CCM_STATE__ERROR) != 0U)
  {
    return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  }

  if ((ctx->add_len > 0U) && !((ctx->state & CCM_STATE__AUTH_DATA_FINISHED) != 0U))
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  /* Tag has a variable length */
  (void) memset(mac, 0, sizeof(mac));

  /* Generate the authentication TAG */
  if (HAL_CRYP_CCM_GenerateAuthTAG(pCCM, (uint32_t *)mac, ST_CRYP_TIMEOUT) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  if (tag != NULL)
  {
    (void) memcpy(tag, mac, tag_len);
  }

  mbedtls_ccm_clear_state(ctx);

  mbedtls_platform_zeroize(ctx->ccm_key, sizeof(ctx->ccm_key));

  return 0;
}

/*
 * Authenticated encryption or decryption
 */
static int ccm_auth_crypt(mbedtls_ccm_context *ctx, int mode, size_t length,
                          const unsigned char *iv, size_t iv_len,
                          const unsigned char *add, size_t add_len,
                          const unsigned char *input, unsigned char *output,
                          unsigned char *tag, size_t tag_len)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  size_t olen;

  ret = mbedtls_ccm_starts(ctx, mode, iv, iv_len);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_ccm_set_lengths(ctx, add_len, length, tag_len);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_ccm_update_ad(ctx, add, add_len);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_ccm_update(ctx, input, length,
                           output, length, &olen);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_ccm_finish(ctx, output, length, &olen, tag, tag_len);
  if (ret != 0)
  {
    return ret;
  }

  return 0;
}

/*
 * Authenticated encryption start
 */
int mbedtls_ccm_star_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
                                     const unsigned char *iv, size_t iv_len,
                                     const unsigned char *add, size_t add_len,
                                     const unsigned char *input, unsigned char *output,
                                     unsigned char *tag, size_t tag_len)
{
  return ccm_auth_crypt(ctx, MBEDTLS_CCM_STAR_ENCRYPT, length, iv, iv_len,
                        add, add_len, input, output, tag, tag_len);
}

/*
 * Authenticated encryption
 */
int mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *add, size_t add_len,
                                const unsigned char *input, unsigned char *output,
                                unsigned char *tag, size_t tag_len)
{
  return ccm_auth_crypt(ctx, MBEDTLS_CCM_ENCRYPT, length,
                        iv, iv_len, add, add_len, input, output, tag, tag_len);
}

/*
 * Authenticated decryption
 */
static int ccm_auth_decrypt(mbedtls_ccm_context *ctx, int mode, size_t length,
                            const unsigned char *iv, size_t iv_len,
                            const unsigned char *add, size_t add_len,
                            const unsigned char *input, unsigned char *output,
                            const unsigned char *tag, size_t tag_len)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  unsigned char check_tag[16];
  unsigned char i = 0;
  uint32_t diff   = 0;

  ret = ccm_auth_crypt(ctx, mode, length,
                       iv, iv_len, add, add_len,
                       input, output, check_tag, tag_len);
  if (ret != 0)
  {
    return ret;
  }

  /* Check tag in "constant-time" */
  diff = 0;
  for (i = 0; i < tag_len; i++)
  {
    diff |= (uint32_t)tag[i] ^ check_tag[i];
  }

  if (diff != 0U)
  {
    mbedtls_platform_zeroize(output, length);
    return (MBEDTLS_ERR_CCM_AUTH_FAILED);
  }

  return 0;
}

/*
 * Authenticated decryption start
 */
int mbedtls_ccm_star_auth_decrypt(mbedtls_ccm_context *ctx, size_t length,
                                  const unsigned char *iv, size_t iv_len,
                                  const unsigned char *add, size_t add_len,
                                  const unsigned char *input, unsigned char *output,
                                  const unsigned char *tag, size_t tag_len)
{
  return ccm_auth_decrypt(ctx, MBEDTLS_CCM_STAR_DECRYPT, length,
                          iv, iv_len, add, add_len,
                          input, output, tag, tag_len);
}

/*
 * Authenticated decryption
 */
int mbedtls_ccm_auth_decrypt(mbedtls_ccm_context *ctx, size_t length,
                             const unsigned char *iv, size_t iv_len,
                             const unsigned char *add, size_t add_len,
                             const unsigned char *input, unsigned char *output,
                             const unsigned char *tag, size_t tag_len)
{
  return (ccm_auth_decrypt(ctx, MBEDTLS_CCM_DECRYPT, length,
                           iv, iv_len, add, add_len,
                           input, output, tag, tag_len));
}

#endif /* MBEDTLS_HAL_CCM_ALT */
#endif /* USE_HAL_CRYP_MODULE */
#endif /* MBEDTLS_CCM_ALT */
#endif /* MBEDTLS_CCM_C */
