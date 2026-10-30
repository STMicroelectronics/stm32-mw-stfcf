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
  * @brief This file contains GCM definitions and functions based on STM32 AES
  *        hardware crypto accelerator.
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
#ifndef MBEDTLS_HAL_GCM_ALT_H
#define MBEDTLS_HAL_GCM_ALT_H

#if defined(MBEDTLS_GCM_ALT)
/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_HAL_GCM_ALT)

#if (defined(USE_HAL_AES_MODULE) && (USE_HAL_AES_MODULE == 1U)) \
    || (defined(USE_HAL_CRYP_MODULE) && (USE_HAL_CRYP_MODULE == 1U))

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_HAL_GCM_TYPES GCM Context Types
  * @ingroup MBEDTLS_IMPLEMENTATION_HAL
  * @brief GCM context structure definitions for mbedTLS HAL.
  * @{
  */

/**
  * @brief          AES context structure
  *
  */
typedef struct mbedtls_gcm_context
{
#if ((defined(USE_HAL_AES_MODULE) && (USE_HAL_AES_MODULE == 1U)))
  hal_aes_gcm_config_t p_gcm_config;    /* AES GCM_GMAC configuration structure */
#endif /* USE_HAL_AES_MODULE */
#if ((defined(USE_HAL_CRYP_MODULE) && (USE_HAL_CRYP_MODULE == 1U)))
  hal_cryp_gcm_config_t p_gcm_config;    /* AES GCM_GMAC configuration structure */
#endif /* USE_HAL_AES_MODULE */
  uint32_t Keysize;                     /* The key size in bits */
  uint32_t gcm_key[8];                  /* Encryption/Decryption key           */
  uint32_t ctx_save_cr;                 /* Saved HW context for multi-instance */
  uint64_t len;                         /* total length of the encrypted data. */
  unsigned char y[16];               /*!< The Y working value. */
  unsigned char buf[16];             /*!< The buf working value. */
  int mode;                             /* The operation to perform:
                                               #MBEDTLS_GCM_ENCRYPT or
                                               #MBEDTLS_GCM_DECRYPT.             */
  uint64_t remain_len;           /*! remain length of the non encrypted data. */
}
mbedtls_gcm_context;

/**
  * @}
  */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAL_GCM_ALT */
#endif /* USE_HAL_AES/CRYP_MODULE */
#endif /* MBEDTLS_GCM_ALT */
#endif /* MBEDTLS_HAL_GCM_ALT_H */
