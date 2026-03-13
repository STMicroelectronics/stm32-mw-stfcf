/**
  ******************************************************************************
  * @file    ccm_alt.h
  * @brief   Header for ccm_alt module
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
  * @brief This file provides an API for the CCM authenticated encryption
  *        mode for block ciphers based on STM32 AES hardware crypto
  *        accelerator.
  *
  * CCM combines Counter mode encryption with CBC-MAC authentication
  * for 128-bit block ciphers.
  *
  * Input to CCM includes the following elements:
  * <ul><li>Payload - data that is both authenticated and encrypted.</li>
  * <li>Associated data (Adata) - data that is authenticated but not
  * encrypted, For example, a header.</li>
  * <li>Nonce - A unique value that is assigned to the payload and the
  * associated data.</li></ul>
  *
  * Definition of CCM:
  * http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
  * RFC 3610 "Counter with CBC-MAC (CCM)"
  *
  * Related:
  * RFC 5116 "An Interface and Algorithms for Authenticated Encryption"
  *
  * Definition of CCM*:
  * IEEE 802.15.4 - IEEE Standard for Local and metropolitan area networks
  * Integer representation is fixed most-significant-octet-first order and
  * the representation of octets is most-significant-bit-first order. This is
  * consistent with RFC 3610.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_STCRYPTOLIB_CCM_ALT_H
#define MBEDTLS_STCRYPTOLIB_CCM_ALT_H

#if defined(MBEDTLS_CCM_ALT)
/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_STCRYPTOLIB_CCM_ALT)
#include "cmox_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_CCM_ALT_TYPES STCRYPTOLIB CCM Types
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @{
  */


/**
  * @brief          AES context structure
  *
  */
typedef struct mbedtls_ccm_context
{
  uint8_t aes_key[32];               /*!< Encryption/Decryption key */
  size_t aes_key_size;               /*!< Aes Key size */
  cmox_cipher_handle_t *cipher_ctx;  /*!< Cipher ctx */
  cmox_ccm_handle_t ccm_ctx;         /*!< ccm ctx */
  int mode;                          /*!< Mode : encrypt or decrypt */
  size_t plaintext_len;                /* Total plaintext length */
  size_t add_len;                      /* Total authentication data length */
  size_t tag_len;                      /* Total tag length */
  unsigned int state;                           /* Working value holding context's
                                          state. Used for chunked data input */
  unsigned char y[16];                 /* The Y working buffer */
  unsigned int q;                      /* The Q working value */
  uint32_t iv_len_copy;                 /*!< IV length copy  */
}
mbedtls_ccm_context;

/**
  * @}
  */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_STCRYPTOLIB_CCM_ALT */

#endif /* MBEDTLS_CCM_ALT */

#endif /* MBEDTLS_STCRYPTOLIB_CCM_ALT_H */
