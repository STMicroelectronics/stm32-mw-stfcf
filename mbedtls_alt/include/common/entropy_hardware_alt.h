/**
  ******************************************************************************
  * @file    entropy_hardware_alt.h
  * @brief   Header for entropy_hardware_alt module
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
  *        and function alternatives for the Hardware Entropy Source.
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef ENTROPY_HARDWARE_ALT_H
#define ENTROPY_HARDWARE_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#if !defined(MBEDTLS_CONFIG_FILE)
#include "../../../templates/mx_stfcf_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif /* !MBEDTLS_CONFIG_FILE */

#if !defined(MBEDTLS_HAL_ENTROPY_HARDWARE_ALT)
#warning "Entropy Hardware Alt, Define not supported"
#endif /* MBEDTLS_HAL_ENTROPY_HARDWARE_ALT */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* ENTROPY_HARDWARE_ALT_H */
