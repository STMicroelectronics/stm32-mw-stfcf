/**
  ******************************************************************************
  * @file    aes_ccm_alt.c
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

#if defined(MBEDTLS_STCRYPTOLIB_CCM_ALT)

/* Parameter validation macros */
/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_CCM_ALT_FUNCTIONS STCRYPTOLIB CCM Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief Public API functions for STCRYPTOLIB CCM alternate implementation.
  * @{
  */

/*
 * initializes the specified CCM context
 */
void mbedtls_ccm_init(mbedtls_ccm_context *ctx)
{
  (void)memset(ctx, 0, sizeof(mbedtls_ccm_context));

  /* Init the STCryptoLib */
  cmox_init_arg_t init_arg;
  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  cmox_initialize(&init_arg);
}

int mbedtls_ccm_setkey(mbedtls_ccm_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits)
{
  if (keybits > 256U)
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  (void)memcpy(ctx->aes_key, key, keybits / 8U);
  ctx->aes_key_size = keybits / 8U;

  return 0;
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

/** @cond DOXYGEN_SHOULD_SKIP_THIS */
static void mbedtls_ccm_clear_state(mbedtls_ccm_context *ctx)
{
  ctx->state = CCM_STATE__CLEAR;
  (void) memset(ctx->y, 0, 16);
}
/** @endcond */

/* This function starts a CCM encryption or decryption operation */
int mbedtls_ccm_starts(mbedtls_ccm_context *ctx,
                       int mode,
                       const unsigned char *iv,
                       size_t iv_len)
{
  /* STCryptoLib return value */
  cmox_cipher_retval_t retval;

  /* Also implies q is within bounds */
  if ((iv_len < 7U) || (iv_len > 13U))
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }
  /* Store the values of mode and q in the context. */
  ctx->mode = mode;
  ctx->q = 16U - 1U - iv_len;

  if (mode == MBEDTLS_CCM_ENCRYPT)
  {
    ctx->cipher_ctx = cmox_ccm_construct(&ctx->ccm_ctx, CMOX_AES_CCM_ENC) ;
    ctx->mode = MBEDTLS_CCM_ENCRYPT;
  }
  else
  {
    ctx->cipher_ctx = cmox_ccm_construct(&ctx->ccm_ctx, CMOX_AES_CCM_DEC);
    ctx->mode = MBEDTLS_CCM_DECRYPT;
  }

  retval = cmox_cipher_init(ctx->cipher_ctx);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  /* Load key from mbed to cmox ctx */
  retval = cmox_cipher_setKey(ctx->cipher_ctx, ctx->aes_key,
                              ctx->aes_key_size);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }
  /* Store iv and iv_len in the context. */
  memcpy(ctx->y, iv, iv_len);
  ctx->iv_len_copy = iv_len;
  ctx->state |= CCM_STATE__STARTED;
  return 0;
}

int mbedtls_ccm_set_lengths(mbedtls_ccm_context *ctx,
                            size_t total_ad_len,
                            size_t plaintext_len,
                            size_t tag_len)
{
  cmox_cipher_retval_t retval;  /* STCryptoLib return value */
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

  /* Set the size of the tag for AEAD cipher */
  retval = cmox_cipher_setTagLen(ctx->cipher_ctx, ctx->tag_len);

  /* Set the total payload size only for CCM AEAD cipher */
  retval = cmox_cipher_setPayloadLen(ctx->cipher_ctx, plaintext_len);

  /* Set the total authenticated data size only for CCM AEAD cipher */
  retval = cmox_cipher_setADLen(ctx->cipher_ctx, ctx->add_len);

  /* Set the initialization vector/nonce to be used with the cipher algorithm. */
  retval = cmox_cipher_setIV(ctx->cipher_ctx, ctx->y, ctx->iv_len_copy);

  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  ctx->state |= CCM_STATE__LENGTHS_SET;
  return 0;
}

/* feeds an input buffer as associated data in a CCM encryption or decryption operation. */
int mbedtls_ccm_update_ad(mbedtls_ccm_context *ctx,
                          const unsigned char *add,
                          size_t add_len)
{
  cmox_cipher_retval_t retval;  /* STCryptoLib return value */

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

      /* blocks (B) associated to the Associated Data (A) */
      retval = cmox_cipher_appendAD(ctx->cipher_ctx, add, add_len);

      if (retval != CMOX_CIPHER_SUCCESS)
      {
        return MBEDTLS_ERR_CCM_BAD_INPUT;
      }
      ctx->state |= CCM_STATE__AUTH_DATA_FINISHED;
    }
  }

  return 0;
}

/* feeds an input buffer into an ongoing CCM encryption or decryption operation. */
int mbedtls_ccm_update(mbedtls_ccm_context *ctx,
                       const unsigned char *input, size_t input_len,
                       unsigned char *output, size_t output_size,
                       size_t *output_len)
{


  cmox_cipher_retval_t retval; /* STCryptoLib return value */
  size_t computed_size = 0;    /* Size computed by STCryptoLib */

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
  /* Append part or the totality of the plaintext/ciphertext and return the
     corresponding ciphertext/plaintext
   */
  retval = cmox_cipher_append(ctx->cipher_ctx, input, input_len, output,
                              &computed_size);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  *output_len = computed_size;
  return 0;
}

/*  This function finishes the CCM operation and generates the authentication tag. */
int mbedtls_ccm_finish(mbedtls_ccm_context *ctx,
                       unsigned char *tag, size_t tag_len)
{
  cmox_cipher_retval_t retval;  /* STCryptoLib return value */
  size_t computed_size = 0;     /* Size computed by STCryptoLib */
  uint32_t fault_check;

  if ((ctx->state & CCM_STATE__ERROR) != 0U)
  {
    return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  }

  if ((ctx->add_len > 0U) && !((ctx->state & CCM_STATE__AUTH_DATA_FINISHED) != 0U))
  {
    return MBEDTLS_ERR_CCM_BAD_INPUT;
  }

  if (ctx->mode == MBEDTLS_CCM_ENCRYPT)
  {
    /* Generate the authenticated tag in case the AEAD operation is an encryption. */
    retval = cmox_cipher_generateTag(ctx->cipher_ctx, tag, &computed_size);
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    if (tag_len != computed_size)
    {
      return MBEDTLS_ERR_CCM_AUTH_FAILED;
    }
  }
  else
  {
    /* Authenticate the processed data with the given tag */
    retval = cmox_cipher_verifyTag(ctx->cipher_ctx, tag, &fault_check);
    if ((fault_check != CMOX_CIPHER_AUTH_SUCCESS) && (retval != CMOX_CIPHER_AUTH_SUCCESS))
    {
      return MBEDTLS_ERR_CCM_AUTH_FAILED;
    }
  }

  mbedtls_ccm_clear_state(ctx);

  mbedtls_platform_zeroize(ctx->aes_key, sizeof(ctx->aes_key));

  return 0;
}

/** @cond DOXYGEN_SHOULD_SKIP_THIS */
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

  ret = mbedtls_ccm_finish(ctx, tag, tag_len);
  if (ret != 0)
  {
    return ret;
  }

  return 0;
}
/** @endcond */

/*
 * Authenticated encryption
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

int mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *add, size_t add_len,
                                const unsigned char *input, unsigned char *output,
                                unsigned char *tag, size_t tag_len)
{
  return ccm_auth_crypt(ctx, MBEDTLS_CCM_ENCRYPT, length,
                        iv, iv_len, add, add_len, input, output, tag, tag_len);
}

/** @cond DOXYGEN_SHOULD_SKIP_THIS */
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
  ret = ccm_auth_crypt(ctx, mode, length,
                       iv, iv_len, add, add_len,
                       input, output, (unsigned char *)tag, tag_len);
  if (ret != 0)
  {
    return ret;
  }

  return 0;
}
/** @endcond */

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

/**
  * @}
  */

#endif /* MBEDTLS_STCRYPTOLIB_CCM_ALT */
#endif /* MBEDTLS_CCM_ALT */
#endif /* MBEDTLS_CCM_C */
