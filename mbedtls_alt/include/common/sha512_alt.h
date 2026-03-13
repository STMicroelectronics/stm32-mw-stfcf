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
  * @brief This file is a router to header files which contain definitions
  *        and function alternatives for SHA-384 and SHA-512.
  *
  * The Secure Hash Algorithms 384 and 512 (SHA-384 and SHA-512) cryptographic
  * hash functions are defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
  *
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_SHA512_ALT_H
#define MBEDTLS_SHA512_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if defined (MBEDTLS_SHA512_ALT)

#if defined(MBEDTLS_HAL_SHA512_ALT)
#include "../hal/hal_sha512_alt.h"
#elif defined(MBEDTLS_STCRYPTOLIB_SHA512_ALT)
#include "../stcryptolib/stcryptolib_sha512_alt.h"
#else /* MBEDTLS_STCRYPTOLIB_SHA512_ALT */
#warning "SHA-512 Alt, Define not supported"
#endif /* MBEDTLS_HAL_SHA512_ALT */

#endif /* MBEDTLS_SHA512_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_SHA512_ALT_H */
