/**
  ******************************************************************************
  * @file    sha256_alt.h
  * @brief   Header for sha256_alt module
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
/**
  * @brief This file contains SHA-224 and SHA-256 definitions and functions
  *        based on STM32 HASH hardware crypto accelerator.
  *
  * The Secure Hash Algorithms 224 and 256 (SHA-224 and SHA-256) cryptographic
  * hash functions are defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_HAL_SHA256_ALT_H
#define MBEDTLS_HAL_SHA256_ALT_H

#if defined (MBEDTLS_SHA256_ALT)

#if defined(MBEDTLS_HAL_SHA256_ALT)

#ifdef __cplusplus
extern "C" {
#endif

/**
  * @brief SHA-256 context structure.
  *
  * The structure is used both for SHA-256 and for SHA-224 checksum calculations.
  * The choice between these two is made in the call to mbedtls_sha256_starts_ret().
  *
  */

/** @defgroup MBEDTLS_IMPLEMENTATION_HAL_SHA256_TYPES SHA-256 Context Types
  * @ingroup MBEDTLS_IMPLEMENTATION_HAL
  * @{
  */

typedef struct mbedtls_sha256_context
{
  int is224;                    /*!< 0 = use SHA256, 1 = use SHA224 */
  uint32_t output_size_byte;    /*!< output length */
  uint32_t hash_size;
}
mbedtls_sha256_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAL_SHA256_ALT */
#endif /* MBEDTLS_SHA256_ALT */
#endif /* MBEDTLS_HAL_SHA256_ALT_H */

/**
  * @}
  */
