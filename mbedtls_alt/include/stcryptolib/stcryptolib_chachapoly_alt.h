/**
  ******************************************************************************
  * @file    chachapoly_alt.h
  * @brief   Header for chachapoly_alt module
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
  * @file chachapoly_alt.h
  *
  * @brief   This file contains the AEAD-ChaCha20-Poly1305 definitions and
  *          functions based on STM32 crypto library.
  *
  *          ChaCha20-Poly1305 is an algorithm for Authenticated Encryption
  *          with Associated Data (AEAD) that can be used to encrypt and
  *          authenticate data. It is based on ChaCha20 and Poly1305 by Daniel
  *          Bernstein and was standardized in RFC 7539.
  *
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT_H
#define MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT_H

#if defined(MBEDTLS_CHACHAPOLY_ALT)
/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT)
#include "cmox_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_CHACHAPOLY_ALT_TYPES STCRYPTOLIB ChaChaPoly Types
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief ChaChaPoly context structure definitions for STCRYPTOLIB.
  * @{
  */

/**
  * @brief          chachapoly context structure
  *
  */
typedef struct mbedtls_chachapoly_context
{
  uint8_t aes_key[32];               /*!< Encryption/Decryption key */
  cmox_cipher_handle_t *cipher_ctx;  /*!< Cipher ctx */
  cmox_chachapoly_handle_t cha_ctx;  /*!< Chachapoly ctx */
  int mode;                          /*!< Mode : encrypt or decrypt */
}
mbedtls_chachapoly_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT */

#endif /* MBEDTLS_CHACHAPOLY_ALT */

#endif /* MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT_H */

/**
  * @}
  */
