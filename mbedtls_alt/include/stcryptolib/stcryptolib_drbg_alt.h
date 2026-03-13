/**
  ******************************************************************************
  * @file    drbg_alt.h
  * @brief   Header for drbg_alt module
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * Copyright The Mbed TLS Contributors
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef STCRYPTOLIB_DRBG_ALT_H
#define STCRYPTOLIB_DRBG_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include <stddef.h>
#include "cmox_crypto.h"
#include <psa/crypto.h>

/* Exported functions ------------------------------------------------------- */

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_DRBG_ALT_API STCRYPTOLIB DRBG Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief DRBG API definitions for STCRYPTOLIB.
  * @{
  */

int32_t DRBG_DeInit(void);
int32_t DRBG_Init(void);
int32_t DRBG_GetBytes(uint8_t *output, size_t length, size_t *output_length);

#ifdef __cplusplus
}
#endif

#endif /* STCRYPTOLIB_DRBG_ALT_H */

/**
  * @}
  */
