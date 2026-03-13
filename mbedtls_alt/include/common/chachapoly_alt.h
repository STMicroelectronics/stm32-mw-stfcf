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
  * @brief This file is a router to header files which contain
  *        AEAD-ChaCha20-Poly1305 definitions and function alternatives.
  *
  * ChaCha20-Poly1305 is an algorithm for Authenticated Encryption with
  * Associated Data (AEAD) that can be used to encrypt and authenticate data.
  * It is based on ChaCha20 and Poly1305 by Daniel Bernstein and was
  * standardized in RFC 7539.
  *
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_CHACHAPOLY_ALT_H
#define MBEDTLS_CHACHAPOLY_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_CHACHAPOLY_ALT)

#if defined(MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT)
#include "../stcryptolib/stcryptolib_chachapoly_alt.h"
#else /* MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT */
#warning "ChaChaPoly Alt, Define not supported"
#endif /* MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT */

#endif /* MBEDTLS_CHACHAPOLY_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CHACHAPOLY_ALT_H */
