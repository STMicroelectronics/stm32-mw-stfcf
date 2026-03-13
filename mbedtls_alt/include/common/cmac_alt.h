/**
  ******************************************************************************
  * @file    cmac_alt.h
  * @brief   Header for cmac_alt module
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
  * @brief This file is a router to header files which contain CMAC definitions
  *        and function alternatives.
  *
  * The Cipher-based Message Authentication Code (CMAC) Mode for
  * Authentication is defined in <em>RFC-4493: The AES-CMAC Algorithm</em>.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_CMAC_ALT_H
#define MBEDTLS_CMAC_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if defined (MBEDTLS_CMAC_ALT)

#if defined(MBEDTLS_STCRYPTOLIB_CMAC_ALT)
#include "../stcryptolib/stcryptolib_cmac_alt.h"
#else /* MBEDTLS_STCRYPTOLIB_CMAC_ALT */
#warning "CMAC Alt, Define not supported"
#endif /* MBEDTLS_STCRYPTOLIB_CMAC_ALT */

#endif /* MBEDTLS_CMAC_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CMAC_ALT_H */
