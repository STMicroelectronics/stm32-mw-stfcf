/**
  ******************************************************************************
  * @file    stcryptolib_aes_alt.h
  * @brief   Sub-Header for aes_alt module
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
  * @brief   This file contains AES definitions and functions based on STM32
  *          crypto library.
  *
  *          The Advanced Encryption Standard (AES) specifies a FIPS-approved
  *          cryptographic algorithm that can be used to protect electronic
  *          data.
  *
  *          The AES algorithm is a symmetric block cipher that can
  *          encrypt and decrypt information. For more information, see
  *          <em>FIPS Publication 197: Advanced Encryption Standard</em> and
  *          <em>ISO/IEC 18033-2:2006: Information technology -- Security
  *          techniques -- Encryption algorithms -- Part 2: Asymmetric
  *          ciphers</em>.
  *
  *          The AES-XTS block mode is standardized by NIST SP 800-38E
  *          <https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38e.pdf>
  *          and described in detail by IEEE P1619
  *          <https://ieeexplore.ieee.org/servlet/opac?punumber=4375278>.
  */

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB mbedTLS STCRYPTOLIB Implementation
  * @ingroup MBEDTLS_IMPLEMENTATION
  * @brief STCRYPTOLIB-specific implementation for mbedTLS.
  * @{
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_STCRYPTOLIB_AES_ALT_H
#define MBEDTLS_STCRYPTOLIB_AES_ALT_H

#if defined(MBEDTLS_AES_ALT)

#if defined(MBEDTLS_STCRYPTOLIB_AES_ALT)
#include "cmox_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_AES_ALT_TYPES STCRYPTOLIB AES Types
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief AES context structure definitions for STCRYPTOLIB.
  * @{
  */

/**
  * @brief          AES context structure
  */
typedef struct
{
  uint8_t aes_key[32];               /*!< Encryption/Decryption key */
  size_t aes_key_size;               /*!< Aes Key size */
  cmox_cipher_handle_t *cipher_ctx;  /*!< Cipher ctx */
  cmox_cbc_handle_t cbc_ctx;         /*!< Cbc ctx */
  cmox_ecb_handle_t ecb_ctx;         /*!< Ecb ctx */
  uint8_t ctx_init;                  /*!< Context init indicator */
}
mbedtls_aes_context;

#if defined(MBEDTLS_CIPHER_MODE_XTS)
/**
  * @brief The AES XTS context-type definition.
  */
typedef struct mbedtls_aes_xts_context
{
  mbedtls_aes_context crypt; /*!< The AES context to use for AES block
                                        encryption or decryption. */
  mbedtls_aes_context tweak; /*!< The AES context used for tweak
                                        computation. */
} mbedtls_aes_xts_context;
#endif /* MBEDTLS_CIPHER_MODE_XTS */


#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_STCRYPTOLIB_AES_ALT */

#endif /* MBEDTLS_AES_ALT */
#endif /* MBEDTLS_STCRYPTOLIB_AES_ALT_H */

/**
  * @}
  */

/**
  * @}
  */
