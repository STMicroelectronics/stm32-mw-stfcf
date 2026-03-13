/**
  ******************************************************************************
  * @file    sha512_alt.h
  * @brief   Header for sha512_alt module
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
  * @brief This file contains SHA-384 and SHA-512 definitions and functions
  *        based on STM32 HASH hardware crypto accelerator.
  *
  * The Secure Hash Algorithms 384 and 512 (SHA-384 and SHA-512) cryptographic
  * hash functions are defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_HAL_SHA512_ALT_H
#define MBEDTLS_HAL_SHA512_ALT_H

#if defined (MBEDTLS_SHA512_ALT)

#if defined(MBEDTLS_HAL_SHA512_ALT)

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_HAL_SHA512_TYPES SHA-512 Context Types
  * @ingroup MBEDTLS_IMPLEMENTATION_HAL
  * @{
  */


/**
  * @brief          SHA-512 context structure
  *
  *                 The structure is used both for SHA-512 and for SHA-384
  *                 checksum calculations. The choice between these two is
  *                 made in the call to mbedtls_sha512_starts_ret().
  */
typedef struct mbedtls_sha512_context
{
  int is384;                    /*!< 0 = use SHA512, 1 = use SHA384 */
  uint32_t output_size_byte;    /*!< output length */
  uint32_t hash_size;
}
mbedtls_sha512_context;

#ifdef __cplusplus
}
#endif

/**
  * @}
  */

#endif /* MBEDTLS_HAL_SHA512_ALT */
#endif /* MBEDTLS_SHA512_ALT */
#endif /* MBEDTLS_HAL_SHA512_ALT_H */
