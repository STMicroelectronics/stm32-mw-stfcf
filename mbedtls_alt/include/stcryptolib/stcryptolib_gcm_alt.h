/**
  ******************************************************************************
  * @file    gcm_alt.h
  * @brief   Header for gcm_alt module
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
  * This file contains GCM definitions and functions based on STM32
  *          crypto library.
  *
  * The Galois/Counter Mode (GCM) for 128-bit block ciphers is defined
  * in <em>D. McGrew, J. Viega, The Galois/Counter Mode of Operation
  * (GCM), Natl. Inst. Stand. Technol.</em>
  *
  * For more information on GCM, see <em>NIST SP 800-38D: Recommendation for
  * Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC</em>.
  *
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_STCRYPTOLIB_GCM_ALT_H
#define MBEDTLS_STCRYPTOLIB_GCM_ALT_H

#if defined(MBEDTLS_GCM_ALT)
/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_STCRYPTOLIB_GCM_ALT)
#include "cmox_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_GCM_ALT_TYPES STCRYPTOLIB GCM Types
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief GCM context structure definitions for STCRYPTOLIB.
  * @{
  */

/**
  * @brief          AES context structure
  *
  */
typedef struct mbedtls_gcm_context
{
  uint8_t aes_key[32];               /*!< Encryption/Decryption key */
  size_t aes_key_size;               /*!< Aes Key size */
  cmox_cipher_handle_t *cipher_ctx;  /*!< Cipher ctx */
  cmox_gcm_handle_t gcm_ctx;         /*!< Gcm ctx */
  int mode;                          /*!< Mode : encrypt or decrypt */
}
mbedtls_gcm_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_STCRYPTOLIB_GCM_ALT */

#endif /* MBEDTLS_GCM_ALT */

#endif /* MBEDTLS_STCRYPTOLIB_GCM_ALT_H */

/**
  * @}
  */
