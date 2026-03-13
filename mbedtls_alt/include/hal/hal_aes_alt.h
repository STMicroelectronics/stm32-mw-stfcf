/**
  ******************************************************************************
  * @file    hal_aes_alt.h
  * @brief   Header for aes_alt module
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
  * @brief   This file contains AES definitions and functions based on STM32 AES
  *          hardware crypto accelerator.
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

/** @defgroup MBEDTLS_IMPLEMENTATION mbedTLS Implementation
  * @brief Implementation for mbedTLS integration.
  * @{
  */

/** @defgroup MBEDTLS_IMPLEMENTATION_HAL mbedTLS HAL Implementation
  * @ingroup MBEDTLS_IMPLEMENTATION
  * @brief HAL-specific implementation for mbedTLS.
  * @{
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_HAL_AES_ALT_H
#define MBEDTLS_HAL_AES_ALT_H

#if defined(MBEDTLS_AES_ALT)

#if defined(MBEDTLS_HAL_AES_ALT)

#if (defined(USE_HAL_AES_MODULE) && (USE_HAL_AES_MODULE == 1U)) \
    || (defined(USE_HAL_CRYP_MODULE) && (USE_HAL_CRYP_MODULE == 1U))

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_HAL_AES_TYPES AES Context Types
  * @ingroup MBEDTLS_IMPLEMENTATION_HAL
  * @brief AES context structure definitions for mbedTLS HAL.
  * @{
  */

typedef struct
{
  uint32_t Keysize;               /*! Size of key */
  uint32_t aes_key[8];            /*! Decryption key */
  uint32_t Algorithm;             /*! Algorithm set (or not) in driver */
  uint32_t ctx_save_cr;           /*! Saved HW context for multi-instance */
}
mbedtls_aes_context;

#if defined(MBEDTLS_CIPHER_MODE_XTS)
/**
  * \brief The AES XTS context-type definition.
  */
typedef struct mbedtls_aes_xts_context
{
  mbedtls_aes_context crypt; /*!< The AES context to use for AES block
                                      encryption or decryption. */
  mbedtls_aes_context tweak; /*!< The AES context used for tweak computation. */
}
mbedtls_aes_xts_context;
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAL_AES_ALT */
#endif /* USE_HAL_AES/CRYP_MODULE */
#endif /* MBEDTLS_AES_ALT */
#endif /* MBEDTLS_HAL_AES_ALT_H */
/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

