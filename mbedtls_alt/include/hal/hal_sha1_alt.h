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
  * @brief This file contains SHA-1 definitions and functions based on STM32 HASH
  *        hardware crypto accelerator.
  *
  * The Secure Hash Algorithm 1 (SHA-1) cryptographic hash function is defined in
  * <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
  *
  * @warning   SHA-1 is considered a weak message digest and its use constitutes
  *            a security risk. We recommend considering stronger message
  *            digests instead.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_HAL_SHA1_ALT_H
#define MBEDTLS_HAL_SHA1_ALT_H

#if defined (MBEDTLS_SHA1_ALT)
/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_HAL_SHA1_ALT)

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_HAL_SHA1_TYPES SHA-1 Context Types
  * @ingroup MBEDTLS_IMPLEMENTATION_HAL
  * @brief SHA-1 context structure definitions for mbedTLS HAL.
  * @{
  */

typedef struct mbedtls_sha1_context
{
  uint32_t output_size_byte;  /*!< output length */
}
mbedtls_sha1_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAL_SHA1_ALT */

#endif /* MBEDTLS_SHA1_ALT */
#endif /* MBEDTLS_HAL_SHA1_ALT_H */

/**
  * @}
  */
