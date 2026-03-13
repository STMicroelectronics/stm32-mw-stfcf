/**
  ******************************************************************************
  * @file    sha1_alt.c
  * @brief   Implementation of mbedtls_alt Middleware SHA1 module
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
  *  This file implements STMicroelectronics SHA1 with HW services based on API
  *  from mbed TLS
  *
  *  The SHA-1 standard was published by NIST in 1993.
  *
  *  http://www.itl.nist.gov/fipspubs/fip180-1.htm
  */

/* Includes ------------------------------------------------------------------*/
#include "common.h"

#if defined(MBEDTLS_SHA1_C)
#if defined(MBEDTLS_SHA1_ALT)
#include "mbedtls/sha1.h"
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_HAL_SHA1_ALT)

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define ST_HASH_TIMEOUT ((uint32_t) 1000)  /* TO in ms for the hash processor */
#define HASH_SIZE 20
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
static hal_hash_handle_t *pHASH = NULL;
static hal_hash_config_t hash_config;
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_HAL_SHA1_ALT_FUNCTIONS HAL SHA1 Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_HAL
  * @brief Public API functions for HAL SHA1 alternate implementation.
  * @{
  */

void mbedtls_sha1_init(mbedtls_sha1_context *ctx)
{
  mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha1_context));

  /* Get the hash handle */
  pHASH = mx_stfcf_mbedtls_alt_hal_hash_gethandle();
}

void mbedtls_sha1_free(mbedtls_sha1_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }

  mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha1_context));
}

void mbedtls_sha1_clone(mbedtls_sha1_context *dst,
                        const mbedtls_sha1_context *src)
{
  *dst = *src;
}

int mbedtls_sha1_starts(mbedtls_sha1_context *ctx)
{
  int ret = 0;

  /* HASH Configuration */

  /* Ensure that HASH is in the right state */
  if ((HAL_HASH_GetState(pHASH) != HAL_HASH_STATE_INIT)
      && (HAL_HASH_GetState(pHASH) != HAL_HASH_STATE_CONFIGURED)
      && (HAL_HASH_GetState(pHASH) != HAL_HASH_HMAC_STATE_CONFIGURED))
  {
    if (HAL_HASH_Abort(pHASH, ST_HASH_TIMEOUT) != HAL_OK)
    {
      return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
  }

  hash_config.algorithm     = HAL_HASH_ALGO_SHA1;
  hash_config.data_swapping = HAL_HASH_DATA_SWAP_BYTE;

  if (HAL_HASH_SetConfig(pHASH, &hash_config) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  return ret;
}

int mbedtls_sha1_update(mbedtls_sha1_context *ctx,
                        const unsigned char *input,
                        size_t ilen)
{
  int ret = 0;

  if (HAL_HASH_Update(pHASH, (const uint8_t *)(input), ilen, ST_HASH_TIMEOUT) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  return ret;
}

int mbedtls_sha1_finish(mbedtls_sha1_context *ctx,
                        unsigned char output[20])
{
  int ret = 0;

  /* Last accumulation for pending bytes in sbuf_len, then trig processing and get digest */
  if (HAL_HASH_Finish(pHASH, output, HASH_SIZE, &(ctx->output_size_byte), ST_HASH_TIMEOUT) != HAL_OK)
  {
    ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    goto exit;
  }

exit :

  return ret;
}

/**
  * @}
  */

#endif /* MBEDTLS_HAL_SHA1_ALT */
#endif /* MBEDTLS_SHA1_ALT*/
#endif /* MBEDTLS_SHA1_C */
