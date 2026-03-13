/**
  ******************************************************************************
  * @file    aes_alt.h
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
  * @brief This file is a router to header files which contain AES definitions
  *        and function alternatives.
  *
  * The Advanced Encryption Standard (AES) specifies a FIPS-approved
  * cryptographic algorithm that can be used to protect electronic
  * data.
  *
  * The AES algorithm is a symmetric block cipher that can
  * encrypt and decrypt information. For more information, see
  * <em>FIPS Publication 197: Advanced Encryption Standard</em> and
  * <em>ISO/IEC 18033-2:2006: Information technology -- Security
  * techniques -- Encryption algorithms -- Part 2: Asymmetric
  * ciphers</em>.
  *
  * The AES-XTS block mode is standardized by NIST SP 800-38E
  * <https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38e.pdf>
  * and described in detail by IEEE P1619
  * <https://ieeexplore.ieee.org/servlet/opac?punumber=4375278>.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_AES_ALT_H
#define MBEDTLS_AES_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_AES_ALT)

#if defined(MBEDTLS_HAL_AES_ALT)
#include "../hal/hal_aes_alt.h"
#elif defined(MBEDTLS_STCRYPTOLIB_AES_ALT)
#include "../stcryptolib/stcryptolib_aes_alt.h"
#else /* MBEDTLS_STCRYPTOLIB_AES_ALT */
#warning "AES Alt, Define not supported"
#endif /* MBEDTLS_HAL_AES_ALT */

#endif /* MBEDTLS_AES_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_AES_ALT_H */
