/**
  ******************************************************************************
  * @file    ccm_alt.h
  * @brief   Header for ccm_alt module
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
  * @brief This file provides an API for the  based on STM32 AES hardware crypto
  *        accelerator.
  * @brief This file is a router to header files which contain definitions and
  *        function alternatives for the CCM authenticated encryption mode for
  *        block ciphers.
  *
  * CCM combines Counter mode encryption with CBC-MAC authentication
  * for 128-bit block ciphers.
  *
  * Input to CCM includes the following elements:
  * <ul><li>Payload - data that is both authenticated and encrypted.</li>
  * <li>Associated data (Adata) - data that is authenticated but not
  * encrypted, For example, a header.</li>
  * <li>Nonce - A unique value that is assigned to the payload and the
  * associated data.</li></ul>
  *
  * Definition of CCM:
  * http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
  * RFC 3610 "Counter with CBC-MAC (CCM)"
  *
  * Related:
  * RFC 5116 "An Interface and Algorithms for Authenticated Encryption"
  *
  * Definition of CCM*:
  * IEEE 802.15.4 - IEEE Standard for Local and metropolitan area networks
  * Integer representation is fixed most-significant-octet-first order and
  * the representation of octets is most-significant-bit-first order. This is
  * consistent with RFC 3610.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_CCM_ALT_H
#define MBEDTLS_CCM_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if defined(MBEDTLS_CCM_ALT)

#if defined(MBEDTLS_HAL_CCM_ALT)
#include "../hal/hal_ccm_alt.h"
#elif defined(MBEDTLS_STCRYPTOLIB_CCM_ALT)
#include "../stcryptolib/stcryptolib_ccm_alt.h"
#else /* MBEDTLS_STCRYPTOLIB_CCM_ALT */
#warning "CCM Alt, Define not supported"
#endif /* MBEDTLS_HAL_CCM_ALT */

#endif /* MBEDTLS_CCM_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CCM_ALT_H */
