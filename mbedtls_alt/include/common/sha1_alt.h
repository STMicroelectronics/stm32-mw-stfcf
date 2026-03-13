/**
  ******************************************************************************
  * @file    sha1_alt.h
  * @brief   Header for sha1_alt module
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
  * @brief This file is a router to header files which contain SHA-1 definitions
  *        and function alternatives.
  *
  * The Secure Hash Algorithm 1 (SHA-1) cryptographic hash function is defined in
  * <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
  *
  * @warning   SHA-1 is considered a weak message digest and its use constitutes
  *            a security risk. We recommend considering stronger message
  *            digests instead.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_SHA1_ALT_H
#define MBEDTLS_SHA1_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if defined (MBEDTLS_SHA1_ALT)

#if defined(MBEDTLS_HAL_SHA1_ALT)
#include "../hal/hal_sha1_alt.h"
#else /* MBEDTLS_HAL_SHA1_ALT */
#warning "SHA-1 Alt, Define not supported"
#endif /* MBEDTLS_HAL_SHA1_ALT */

#endif /* MBEDTLS_SHA1_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_SHA1_ALT_H */
