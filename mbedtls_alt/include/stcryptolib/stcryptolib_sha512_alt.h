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
  *        based on STM32 crypto library.
  *
  * The Secure Hash Algorithms 384 and 512 (SHA-384 and SHA-512) cryptographic
  * hash functions are defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_STCRYPTOLIB_SHA512_ALT_H
#define MBEDTLS_STCRYPTOLIB_SHA512_ALT_H

#if defined (MBEDTLS_SHA512_ALT)

#if defined(MBEDTLS_STCRYPTOLIB_SHA512_ALT)
#include "cmox_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_SHA512_ALT_TYPES STCRYPTOLIB SHA-512 Types
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
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
  cmox_hash_handle_t *hash_ctx;     /*!< Hash ctx*/
  cmox_sha512_handle_t sha512_ctx;  /*!< Sha512 ctx*/
  cmox_sha384_handle_t sha384_ctx;  /*!< Sha384 ctx*/
  size_t dig_len;                   /*!< Digest len generate by STCryptoLib */
  uint8_t is384;                    /*!< 1 if sha384, 0 otherwise */
}
mbedtls_sha512_context;

#ifdef __cplusplus
}
#endif

/**
  * @}
  */

#endif /* MBEDTLS_STCRYPTOLIB_SHA512_ALT */

#endif /* MBEDTLS_SHA512_ALT */
#endif /* MBEDTLS_STCRYPTOLIB_SHA512_ALT_H */
