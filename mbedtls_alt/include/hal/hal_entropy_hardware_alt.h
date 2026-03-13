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
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef HAL_ENTROPY_HARDWARE_ALT_H
#define HAL_ENTROPY_HARDWARE_ALT_H

/* Includes ------------------------------------------------------------------*/
#include "mbedtls/entropy.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */
/* Exported functions ------------------------------------------------------- */

/** @defgroup MBEDTLS_IMPLEMENTATION_HAL_ENTROPY_ALT_FUNCTIONS Entropy Hardware Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_HAL
  * @brief Entropy hardware function(s) for mbedTLS HAL.
  * @{
  */

/**
  * @brief Entropy poll callback for a hardware source (provided to mbed crypto).
  *
  * @param data   Unused parameter (can be NULL).
  * @param output Buffer to hold the random bytes.
  * @param len    The requested number of random bytes.
  * @param olen   Pointer to the actual number of random bytes written to output.
  * @retval 0 on success, or the entropy source failure code from entropy.h on failure.
  * @note   Accepts NULL as its first argument (unused).
  */
int32_t mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);

/**
  * @}
  */

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* HAL_ENTROPY_HARDWARE_ALT_H */
