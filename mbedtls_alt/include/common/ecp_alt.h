/**
  ******************************************************************************
  * @file    ecp_alt.h
  * @brief   Header for ecp_alt module
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
  *        and function alternatives for Elliptic Curves over GF(P) (ECP).
  *
  * The use of ECP in cryptography and TLS is defined in
  * <em>Standards for Efficient Cryptography Group (SECG): SEC1
  * Elliptic Curve Cryptography</em> and
  * <em>RFC-4492: Elliptic Curve Cryptography (ECC) Cipher Suites
  * for Transport Layer Security (TLS)</em>.
  *
  * <em>RFC-2409: The Internet Key Exchange (IKE)</em> defines ECP
  * group types.
  *
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_ECP_ALT_H
#define MBEDTLS_ECP_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if defined (MBEDTLS_ECP_ALT)

#if defined(MBEDTLS_HAL_ECP_ALT)
#include "../hal/hal_ecp_alt.h"
#else /* MBEDTLS_HAL_ECP_ALT */
#warning "ECP Alt, Define not supported"
#endif /* MBEDTLS_HAL_ECP_ALT */

#endif /* MBEDTLS_ECP_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_ECP_ALT_H */
