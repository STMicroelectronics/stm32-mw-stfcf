/**
  ******************************************************************************
  * @file    sha256_alt.c
  * @brief   Implementation of mbedtls_alt SHA256 module
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
  * FIPS-180-2 compliant SHA-256 implementation
  *
  * This file implements SHA256 based on STM32 crypto library.
  *
  *  The SHA-256 Secure Hash Standard was published by NIST in 2002.
  *
  *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
  */

/* Includes ------------------------------------------------------------------*/
#include "common.h"

#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_SHA256_ALT)
#include "mbedtls/sha256.h"
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_STCRYPTOLIB_SHA256_ALT)
/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/

/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_SHA256_ALT_FUNCTIONS STCRYPTOLIB SHA256 Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief Public API functions for STCRYPTOLIB SHA256 alternate implementation.
  * @{
  */

/* Implementation that must never be optimized out by the compiler */
/** @cond DOXYGEN_SHOULD_SKIP_THIS */
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

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
  mbedtls_zeroize(ctx, sizeof(mbedtls_sha256_context));
  /* Init the STCryptoLib */
  cmox_init_arg_t init_arg;
  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  cmox_initialize(&init_arg);

}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }

  mbedtls_zeroize(ctx, sizeof(mbedtls_sha256_context));
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst,
                          const mbedtls_sha256_context *src)
{
  cmox_hash_retval_t retval = 0;
  /* Construct and init the clone ctx */
  if ((src->is224) != 0U)
  {
    dst->hash_ctx = cmox_sha224_construct(&dst->sha224_ctx);
  }
  else
  {
    dst->hash_ctx = cmox_sha256_construct(&dst->sha256_ctx);
  }
  retval = cmox_hash_init(dst->hash_ctx);
  if (retval != CMOX_HASH_SUCCESS)
  {
    return;
  }
}

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
  cmox_hash_retval_t retval = 0;

  if (is224 != 0)
  {
    ctx->hash_ctx = cmox_sha224_construct(&ctx->sha224_ctx);
    ctx->is224 = 1;
  }
  else
  {
    ctx->hash_ctx = cmox_sha256_construct(&ctx->sha256_ctx);
  }
  retval = cmox_hash_init(ctx->hash_ctx);
  if (retval != CMOX_HASH_SUCCESS)
  {
    return MBEDTLS_ERR_SHA256_BAD_INPUT_DATA;
  }

  return 0;
}

int mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx, const unsigned char data[64])
{
  return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input, size_t ilen)
{
  cmox_hash_retval_t retval = 0;

  retval = cmox_hash_append(ctx->hash_ctx, input, ilen);
  if (retval != CMOX_HASH_SUCCESS)
  {
    return MBEDTLS_ERR_SHA256_BAD_INPUT_DATA;
  }

  return 0;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char *output)
{
  cmox_hash_retval_t retval = 0;

  retval = cmox_hash_generateTag(ctx->hash_ctx, output, &ctx->dig_len);
  if (retval != CMOX_HASH_SUCCESS)
  {
    return MBEDTLS_ERR_SHA256_BAD_INPUT_DATA;
  }

  return 0;
}

/**
  * @}
  */

#endif /* MBEDTLS_STCRYPTOLIB_SHA256_ALT */

#endif /* MBEDTLS_SHA256_ALT*/
#endif /* MBEDTLS_SHA256_C */
