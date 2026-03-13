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
  * This file implements SHA256 based on STM32 HASH hardware crypto accelerator.
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

#if defined(MBEDTLS_HAL_SHA256_ALT)
/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define ST_SHA256_TIMEOUT     ((uint32_t) 3)

/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
static  hal_hash_handle_t *pHASH = NULL;
static  hal_hash_config_t hash_config;
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_HAL_SHA256_ALT_FUNCTIONS HAL SHA256 Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_HAL
  * @brief Public API functions for HAL SHA256 alternate implementation.
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

  /* Get the hash handle */
  pHASH = mx_stfcf_mbedtls_alt_hal_hash_gethandle();
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }
  mbedtls_zeroize(ctx, sizeof(mbedtls_sha256_context));
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst, const mbedtls_sha256_context *src)
{
  *dst = *src;
}

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
  /* HASH Configuration */

  /* Ensure that HASH is in the right state */
  if ((HAL_HASH_GetState(pHASH) != HAL_HASH_STATE_INIT)
      && (HAL_HASH_GetState(pHASH) != HAL_HASH_STATE_CONFIGURED)
      && (HAL_HASH_GetState(pHASH) != HAL_HASH_HMAC_STATE_CONFIGURED))
  {
    if (HAL_HASH_Abort(pHASH, ST_SHA256_TIMEOUT) != HAL_OK)
    {
      return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
  }

  ctx->is224 = is224;
  if (ctx->is224 == 0)
  {
    hash_config.algorithm = HAL_HASH_ALGO_SHA256;
  }
  else
  {
    hash_config.algorithm = HAL_HASH_ALGO_SHA224;
  }
  hash_config.data_swapping = HAL_HASH_DATA_SWAP_BYTE;

  if (HAL_HASH_SetConfig(pHASH, &hash_config) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  return 0;
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen)
{
  /* HASH update process in polling mode with several input buffers. */
  if (HAL_HASH_Update(pHASH, (const uint8_t *)(input), ilen, ST_SHA256_TIMEOUT) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  return 0;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char *output)
{
  if (ctx->is224 == 0)
  {
    ctx->hash_size = 32;
  }
  else
  {
    ctx->hash_size = 28;
  }
  /* Last accumulation for pending bytes in sbuf_len, then trig processing and get digest */
  if (HAL_HASH_Finish(pHASH, output, ctx->hash_size, &(ctx->output_size_byte), ST_SHA256_TIMEOUT) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  return 0;
}

/**
  * @}
  */

#endif /* MBEDTLS_HAL_SHA256_ALT */
#endif /* MBEDTLS_SHA256_ALT */
#endif /* MBEDTLS_SHA256_C */
