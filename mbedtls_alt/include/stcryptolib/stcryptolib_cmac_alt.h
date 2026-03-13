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
  * @brief This file contains CMAC definitions and functions based on STM32
  *        crypto library.
  *
  * The Cipher-based Message Authentication Code (CMAC) Mode for
  * Authentication is defined in <em>RFC-4493: The AES-CMAC Algorithm</em>.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_STCRYPTOLIB_CMAC_ALT_H
#define MBEDTLS_STCRYPTOLIB_CMAC_ALT_H

#if defined (MBEDTLS_CMAC_ALT)

#if defined(MBEDTLS_STCRYPTOLIB_CMAC_ALT)
#include "cmox_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_CMAC_ALT_TYPES STCRYPTOLIB CMAC Types
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief CMAC context structure definitions for STCRYPTOLIB.
  * @{
  */

/**
  * @brief          CMAC context structure
  */
struct mbedtls_cmac_context_t
{
  cmox_mac_handle_t *mac_ctx;      /*!< Mac ctx */
  cmox_cmac_handle_t cmac_ctx;     /*!< Cmac ctx */
};

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_STCRYPTOLIB_CMAC_ALT */

#endif /* MBEDTLS_CMAC_ALT */
#endif /* MBEDTLS_STCRYPTOLIB_CMAC_ALT_H */

/**
  * @}
  */
