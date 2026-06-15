/**
  ******************************************************************************
  * @file    chachapoly_alt.c
  * @brief   Implementation of mbedtls_alt CHACHAPOLY module
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
  * This file implements ST ChachaPoly services based on API from mbed TLS
  *
  * - RFC 7539 - ChaCha20 and Poly1305 for IETF Protocols
  * https://www.rfc-editor.org/rfc/rfc7539.html
  *
  */

/* Includes ------------------------------------------------------------------*/
#include "mbedtls/chachapoly.h"

#if defined(MBEDTLS_CHACHAPOLY_C)
#if defined(MBEDTLS_CHACHAPOLY_ALT)
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT)

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_CHACHAPOLY_ALT_FUNCTIONS STCRYPTOLIB CHACHAPOLY Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief Public API functions for STCRYPTOLIB CHACHAPOLY alternate implementation.
  * @{
  */

/**
  * @brief Initialize a context
  */
void mbedtls_chachapoly_init(mbedtls_chachapoly_context *ctx)
{
  (void)memset(ctx, 0, sizeof(mbedtls_chachapoly_context));

  /* Init the STCryptoLib */
  cmox_init_arg_t init_arg;
  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  (void)cmox_initialize(&init_arg);
}

int mbedtls_chachapoly_setkey(mbedtls_chachapoly_context *ctx, const unsigned char key[32])
{
  (void)memcpy(ctx->aes_key, key, 32U);

  return 0;
}

int mbedtls_chachapoly_starts(mbedtls_chachapoly_context *ctx, const unsigned char nonce[12],
                              mbedtls_chachapoly_mode_t mode)
{
  cmox_cipher_retval_t retval;  /* STCryptoLib return value */

  if (mode == MBEDTLS_CHACHAPOLY_ENCRYPT)
  {
    ctx->cipher_ctx = cmox_chachapoly_construct(&ctx->cha_ctx, CMOX_CHACHAPOLY_ENC) ;
    ctx->mode = (int)MBEDTLS_CHACHAPOLY_ENCRYPT;
  }
  else
  {
    ctx->cipher_ctx = cmox_chachapoly_construct(&ctx->cha_ctx, CMOX_CHACHAPOLY_DEC);
    ctx->mode = (int)MBEDTLS_CHACHAPOLY_DECRYPT;
  }

  retval = cmox_cipher_init(ctx->cipher_ctx);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  /* Load key from mbed to cmox ctx */
  retval = cmox_cipher_setKey(ctx->cipher_ctx, ctx->aes_key, 32U);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  retval = cmox_cipher_setIV(ctx->cipher_ctx, nonce, 12U);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  return 0;
}

int mbedtls_chachapoly_update_aad(mbedtls_chachapoly_context *ctx, const unsigned char *aad, size_t aad_len)
{
  cmox_cipher_retval_t retval;  /* STCryptoLib return value */

  retval = cmox_cipher_appendAD(ctx->cipher_ctx, aad, aad_len);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  return 0;
}


int mbedtls_chachapoly_update(mbedtls_chachapoly_context *ctx, size_t len,
                              const unsigned char *input, unsigned char *output)
{
  cmox_cipher_retval_t retval; /* STCryptoLib return value */
  size_t computed_size = 0;    /* Size computed by STCryptoLib */

  if ((output > input) && ((size_t)(output - input) < len))
  {
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  retval = cmox_cipher_append(ctx->cipher_ctx, input, len, output, &computed_size);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  return 0;
}

int mbedtls_chachapoly_finish(mbedtls_chachapoly_context *ctx, unsigned char mac[16])
{
  cmox_cipher_retval_t retval;  /* STCryptoLib return value */
  size_t computed_size = 0;     /* Size computed by STCryptoLib */
  uint32_t fault_check;

  retval = cmox_cipher_setTagLen(ctx->cipher_ctx, 16U);
  if (retval != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  if (ctx->mode == (int)MBEDTLS_CHACHAPOLY_ENCRYPT)
  {
    retval = cmox_cipher_generateTag(ctx->cipher_ctx, mac, &computed_size);
    if (retval != CMOX_CIPHER_SUCCESS)
    {
      return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
    }
  }
  else
  {
    retval = cmox_cipher_verifyTag(ctx->cipher_ctx, mac, &fault_check);
    if ((fault_check != CMOX_CIPHER_AUTH_SUCCESS) && (retval != CMOX_CIPHER_AUTH_SUCCESS))
    {
      return MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED;
    }
  }

  return 0;
}

int mbedtls_chachapoly_encrypt_and_tag(mbedtls_chachapoly_context *ctx, size_t length, const unsigned char nonce[12],
                                       const unsigned char *aad, size_t aad_len, const unsigned char *input,
                                       unsigned char *output, unsigned char tag[16])
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

  ret = mbedtls_chachapoly_starts(ctx, nonce, MBEDTLS_CHACHAPOLY_ENCRYPT);
  if (ret != 0)
  {
    return ret;
  }

  if ((cmox_cipher_setTagLen(ctx->cipher_ctx, 16U)) != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  ret = mbedtls_chachapoly_update_aad(ctx, aad, aad_len);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_chachapoly_update(ctx, length, input, output);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_chachapoly_finish(ctx, tag);
  if (ret != 0)
  {
    return ret;
  }

  return 0;
}

int mbedtls_chachapoly_auth_decrypt(mbedtls_chachapoly_context *ctx, size_t length, const unsigned char nonce[12],
                                    const unsigned char *aad, size_t aad_len, const unsigned char tag[16],
                                    const unsigned char *input, unsigned char *output)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  uint32_t fault_check = CMOX_CIPHER_AUTH_FAIL; /* Fault check variable */

  ret = mbedtls_chachapoly_starts(ctx, nonce, MBEDTLS_CHACHAPOLY_DECRYPT);
  if (ret != 0)
  {
    return ret;
  }

  ret = mbedtls_chachapoly_update_aad(ctx, aad, aad_len);
  if (ret != 0)
  {
    return ret;
  }

  if ((cmox_cipher_setTagLen(ctx->cipher_ctx, 16U)) != CMOX_CIPHER_SUCCESS)
  {
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  ret = mbedtls_chachapoly_update(ctx, length, input, output);
  if (ret != 0)
  {
    return ret;
  }

  if (cmox_cipher_verifyTag(ctx->cipher_ctx, tag, &fault_check) != CMOX_CIPHER_AUTH_SUCCESS)
  {
    mbedtls_platform_zeroize(output, length);
    return MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA;
  }

  /* Verify Fault check variable value */
  if (fault_check != CMOX_CIPHER_AUTH_SUCCESS)
  {
    mbedtls_platform_zeroize(output, length);
    return MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED;
  }

  return 0;
}

void mbedtls_chachapoly_free(mbedtls_chachapoly_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }

  mbedtls_platform_zeroize(ctx, sizeof(mbedtls_chachapoly_context));
}

/**
  * @}
  */

#endif /* MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT */

#endif /* MBEDTLS_CHACHAPOLY_ALT */
#endif /* MBEDTLS_CHACHAPOLY_C */
