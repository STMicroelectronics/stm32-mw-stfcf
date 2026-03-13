/**
  ******************************************************************************
  * @file    rsa_alt.h
  * @brief   Header for rsa_alt module
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
  * @brief This file is a router to header files which contain definitions
  *        and function alternatives for RSA public-key cryptosystem.
  *
  * The RSA public-key cryptosystem is defined in <em>Public-Key
  * Cryptography Standards (PKCS) #1 v1.5: RSA Encryption</em>
  * and <em>Public-Key Cryptography Standards (PKCS) #1 v2.1:
  * RSA Cryptography Specifications</em>.
  *
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_RSA_ALT_H
#define MBEDTLS_RSA_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_RSA_ALT)

#if defined(MBEDTLS_HAL_RSA_ALT)
#include "../hal/hal_rsa_alt.h"
#elif defined(MBEDTLS_STCRYPTOLIB_RSA_ALT)
#include "../stcryptolib/stcryptolib_rsa_alt.h"
#else /* MBEDTLS_STCRYPTOLIB_RSA_ALT */
#warning "RSA Alt, Define not supported"
#endif /* MBEDTLS_HAL_RSA_ALT */

#endif /* MBEDTLS_RSA_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_RSA_ALT_H */
