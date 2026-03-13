/**
  ******************************************************************************
  * @file    sha512_alt.c
  * @brief   Implementation of mbedtls_alt SHA512 module
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
  * FIPS-180-2 compliant SHA-512 implementation
  *
  * This file implements SHA512 based on STM32 crypto library.
  *
  *  The SHA-512 Secure Hash Standard was published by NIST in 2002.
  *
  *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
  */

/* Includes ------------------------------------------------------------------*/
#include "common.h"

#if defined(MBEDTLS_SHA512_C)
#if defined(MBEDTLS_SHA512_ALT)
#include "mbedtls/sha512.h"
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_STCRYPTOLIB_SHA512_ALT)
/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/

/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_SHA512_ALT_FUNCTIONS STCRYPTOLIB SHA512 Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief Public API functions for STCRYPTOLIB SHA512 alternate implementation.
  * @{
  */

/** @cond DOXYGEN_SHOULD_SKIP_THIS */
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

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
  mbedtls_zeroize(ctx, sizeof(mbedtls_sha512_context));
  /* Init the STCryptoLib */
  cmox_init_arg_t init_arg;
  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  cmox_initialize(&init_arg);

}

void mbedtls_sha512_free(mbedtls_sha512_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }

  mbedtls_zeroize(ctx, sizeof(mbedtls_sha512_context));
}

void mbedtls_sha512_clone(mbedtls_sha512_context *dst,
                          const mbedtls_sha512_context *src)
{
  cmox_hash_retval_t retval = 0;
  /* Construct and init the clone ctx */
  if ((src->is384) != 0U)
  {
    dst->hash_ctx = cmox_sha384_construct(&dst->sha384_ctx);
  }
  else
  {
    dst->hash_ctx = cmox_sha512_construct(&dst->sha512_ctx);
  }
  retval = cmox_hash_init(dst->hash_ctx);
  if (retval != CMOX_HASH_SUCCESS)
  {
    return;
  }
}

int mbedtls_sha512_starts(mbedtls_sha512_context *ctx, int is384)
{
  cmox_hash_retval_t retval = 0;

  if (is384 != 0)
  {
    ctx->hash_ctx = cmox_sha384_construct(&ctx->sha384_ctx);
    ctx->is384 = 1;
  }
  else
  {
    ctx->hash_ctx = cmox_sha512_construct(&ctx->sha512_ctx);
  }
  retval = cmox_hash_init(ctx->hash_ctx);
  if (retval != CMOX_HASH_SUCCESS)
  {
    return MBEDTLS_ERR_SHA512_BAD_INPUT_DATA;
  }

  return 0;
}

int mbedtls_internal_sha512_process(mbedtls_sha512_context *ctx, const unsigned char data[128])
{
  return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input, size_t ilen)
{
  cmox_hash_retval_t retval = 0;

  retval = cmox_hash_append(ctx->hash_ctx, input, ilen);
  if (retval != CMOX_HASH_SUCCESS)
  {
    return MBEDTLS_ERR_SHA512_BAD_INPUT_DATA;
  }

  return 0;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx, unsigned char *output)
{
  cmox_hash_retval_t retval = 0;

  retval = cmox_hash_generateTag(ctx->hash_ctx, output, &ctx->dig_len);
  if (retval != CMOX_HASH_SUCCESS)
  {
    return MBEDTLS_ERR_SHA512_BAD_INPUT_DATA;
  }

  return 0;
}

/**
  * @}
  */

#endif /* MBEDTLS_STCRYPTOLIB_SHA512_ALT */

#endif /* MBEDTLS_SHA512_ALT*/
#endif /* MBEDTLS_SHA512_C */
