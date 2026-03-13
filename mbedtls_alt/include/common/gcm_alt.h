/**
  ******************************************************************************
  * @file    gcm_alt.h
  * @brief   Header for gcm_alt.c module
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
  * @brief This file is a router to header files which contain GCM definitions
  *        and function alternatives.
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
#ifndef MBEDTLS_GCM_ALT_H
#define MBEDTLS_GCM_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_GCM_ALT)

#if defined(MBEDTLS_HAL_GCM_ALT)
#include "../hal/hal_gcm_alt.h"
#elif defined(MBEDTLS_STCRYPTOLIB_GCM_ALT)
#include "../stcryptolib/stcryptolib_gcm_alt.h"
#else /* MBEDTLS_STCRYPTOLIB_GCM_ALT */
#warning "GCM Alt, Define not supported"
#endif /* MBEDTLS_HAL_GCM_ALT */

#endif /* MBEDTLS_GCM_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_GCM_ALT_H */
