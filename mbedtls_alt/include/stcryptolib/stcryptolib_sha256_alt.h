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
  *        based on STM32 crypto library.
  *
  * The Secure Hash Algorithms 224 and 256 (SHA-224 and SHA-256) cryptographic
  * hash functions are defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_STCRYPTOLIB_SHA256_ALT_H
#define MBEDTLS_STCRYPTOLIB_SHA256_ALT_H

#if defined (MBEDTLS_SHA256_ALT)

#if defined(MBEDTLS_STCRYPTOLIB_SHA256_ALT)
#include "cmox_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
  * @brief SHA-256 context structure
  *
  * The structure is used both for SHA-256 and for SHA-224
  * checksum calculations. The choice between these two is
  * made in the call to mbedtls_sha256_starts_ret().
  */

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_SHA256_ALT_TYPES STCRYPTOLIB SHA-256 Types
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @{
  */

typedef struct mbedtls_sha256_context
{
  cmox_hash_handle_t *hash_ctx;     /*!< Hash ctx*/
  cmox_sha256_handle_t sha256_ctx;  /*!< Sha256 ctx*/
  cmox_sha224_handle_t sha224_ctx;  /*!< Sha224 ctx*/
  size_t dig_len;                   /*!< Digest len generate by STCryptoLib */
  uint8_t is224;                    /*!< 1 if sha224, 0 otherwise */
}
mbedtls_sha256_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_STCRYPTOLIB_SHA256_ALT */

#endif /* MBEDTLS_SHA256_ALT */
#endif /* MBEDTLS_STCRYPTOLIB_SHA256_ALT_H */

/**
  * @}
  */
