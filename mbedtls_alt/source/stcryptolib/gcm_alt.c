/**
  ******************************************************************************
  * @file    gcm_alt.c
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
  * This file implements GCM based on STM32 crypto library.
  */

/* Includes ------------------------------------------------------------------*/
#include "mbedtls/gcm.h"

#if defined(MBEDTLS_GCM_C)
#if defined(MBEDTLS_GCM_ALT)
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_STCRYPTOLIB_GCM_ALT)

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_GCM_ALT_FUNCTIONS STCRYPTOLIB GCM Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief Public API functions for STCRYPTOLIB GCM alternate implementation.
  * @{
  */

/**
  * @brief Initialize a context
  */
void mbedtls_gcm_init(mbedtls_gcm_context *ctx)
{
  (void)memset(ctx, 0, sizeof(mbedtls_gcm_context));

  /* Init the STCryptoLib */
  cmox_init_arg_t init_arg;
  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  cmox_initialize(&init_arg);
}

int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx, mbedtls_cipher_id_t cipher,
                       const unsigned char *key, unsigned int keybits)
{
  if (keybits > 256U)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  (void)memcpy(ctx->aes_key, key, keybits / 8U);
  ctx->aes_key_size = keybits / 8U;

  return 0;
}

int mbedtls_gcm_starts(mbedtls_gcm_context *ctx, int mode,
                       const unsigned char *iv, size_t iv_len)
{
  cmox_cipher_retval_t retval;  /* STCryptoLib return value */

  /* IV and AD are limited to 2^64 bits, so 2^61 bytes */
  /* IV is not allowed to be zero length */
  if ((iv_len == 0U) || ((((uint64_t) iv_len) >> 61) != 0U))
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  if (mode == MBEDTLS_GCM_ENCRYPT)
  {
    ctx->cipher_ctx = cmox_gcm_construct(&ctx->gcm_ctx, CMOX_AES_GCM_ENC) ;
    ctx->mode = MBEDTLS_GCM_ENCRYPT;
  }
  else
  {
    ctx->cipher_ctx = cmox_gcm_construct(&ctx->gcm_ctx, CMOX_AES_GCM_DEC);
    ctx->mode = MBEDTLS_GCM_DECRYPT;
  }

  retval = cmox_cipher_init(ctx->cipher_ctx);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  /* Load key from mbed to cmox ctx */
  retval = cmox_cipher_setKey(ctx->cipher_ctx, ctx->aes_key,
                              ctx->aes_key_size);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  retval = cmox_cipher_setIV(ctx->cipher_ctx, iv, iv_len);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  return 0;
}

/**
  * @brief mbedtls_gcm_context::buf contains the partial state of the computation of the authentication tag.
  *
  * @details
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
  cmox_cipher_retval_t retval;  /* STCryptoLib return value */

  /* IV is limited to 2^64 bits, so 2^61 bytes */
  if (((uint64_t) add_len >> 61) != 0U)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }
  retval = cmox_cipher_appendAD(ctx->cipher_ctx, add, add_len);

  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  return 0;
}

int mbedtls_gcm_update(mbedtls_gcm_context *ctx,
                       const unsigned char *input, size_t input_length,
                       unsigned char *output, size_t output_size,
                       size_t *output_length)
{

  cmox_cipher_retval_t retval; /* STCryptoLib return value */
  size_t computed_size = 0;    /* Size computed by STCryptoLib */

  if ((output > input) && ((size_t)(output - input) < input_length))
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  retval = cmox_cipher_append(ctx->cipher_ctx, input, input_length, output,
                              &computed_size);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }
  *output_length = input_length;

  return 0;
}

int mbedtls_gcm_finish(mbedtls_gcm_context *ctx,
                       unsigned char *output, size_t output_size,
                       size_t *output_length,
                       unsigned char *tag, size_t tag_len)
{

  cmox_cipher_retval_t retval;  /* STCryptoLib return value */
  size_t computed_size = 0;     /* Size computed by STCryptoLib */
  uint32_t fault_check;

  if ((tag_len > 16U) || (tag_len < 4U))
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  retval = cmox_cipher_setTagLen(ctx->cipher_ctx, tag_len);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  if (ctx->mode == MBEDTLS_GCM_ENCRYPT)
  {
    retval = cmox_cipher_generateTag(ctx->cipher_ctx, tag, &computed_size);
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    if (tag_len != computed_size)
    {
      return MBEDTLS_ERR_GCM_AUTH_FAILED;
    }
  }
  else
  {
    retval = cmox_cipher_verifyTag(ctx->cipher_ctx, tag, &fault_check);
    if ((fault_check != CMOX_CIPHER_AUTH_SUCCESS) && (retval != CMOX_CIPHER_AUTH_SUCCESS))
    {
      return MBEDTLS_ERR_GCM_AUTH_FAILED;
    }
  }

  return 0;
}

int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx, int mode,
                              size_t length,
                              const unsigned char *iv, size_t iv_len,
                              const unsigned char *add, size_t add_len,
                              const unsigned char *input,
                              unsigned char *output, size_t tag_len,
                              unsigned char *tag)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  cmox_cipher_retval_t retval; /* STCryptoLib return value */
  size_t olen = 0;

  /* Mbed TLS allows alternative implementations to only support 12-byte nonces. */
  if (iv_len != 12U)
  {
    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
  }

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

  /* Authentication tag size */
  retval = cmox_cipher_setTagLen(ctx->cipher_ctx, tag_len);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  ret = mbedtls_gcm_update(ctx, input, length, output, length, &olen);
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

int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx, size_t length,
                             const unsigned char *iv, size_t iv_len,
                             const unsigned char *add, size_t add_len,
                             const unsigned char *tag, size_t tag_len,
                             const unsigned char *input,
                             unsigned char *output)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  cmox_cipher_retval_t retval; /* STCryptoLib return value */
  uint32_t fault_check = CMOX_CIPHER_AUTH_FAIL; /* Fault check variable */
  size_t olen = 0;

  ret = mbedtls_gcm_starts(ctx, MBEDTLS_GCM_DECRYPT, iv, iv_len);
  if (ret  != 0)
  {
    return ret;
  }

  ret = mbedtls_gcm_update_ad(ctx, add, add_len);
  if (ret != 0)
  {
    return ret;
  }

  /* Authentication tag size */
  retval = cmox_cipher_setTagLen(ctx->cipher_ctx, tag_len);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  ret = mbedtls_gcm_update(ctx, input, length, output, length, &olen);
  if (ret != 0)
  {
    return ret;
  }

  retval = cmox_cipher_verifyTag(ctx->cipher_ctx, tag, &fault_check);
  if (retval != CMOX_CIPHER_AUTH_SUCCESS)
  {
    mbedtls_platform_zeroize(output, length);
    return MBEDTLS_ERR_GCM_BAD_INPUT;
  }

  /* Verify Fault check variable value */
  if (fault_check != CMOX_CIPHER_AUTH_SUCCESS)
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

/**
  * @}
  */

#endif /* MBEDTLS_STCRYPTOLIB_GCM_ALT */

#endif /* MBEDTLS_GCM_ALT */
#endif /* MBEDTLS_GCM_C */
