/**
  ******************************************************************************
  * @file    Pre_Include_Global.h
  * @brief   Header to enable global STFCF configuration file
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef PRE_INCLUDE_GLOBAL_H_STMicroelectronics_stfcf
#define PRE_INCLUDE_GLOBAL_H_STMicroelectronics_stfcf

#ifdef __cplusplus
extern "C" {
#endif

/* origin-pack: STMicroelectronics::stfcf@3.0.0 */
/* file-format: 1.0.0 */

/* Device headers and defines */


/* RTE Content */
#if (CMSIS_USE_Security_STFCF_PSA_API_1_0_0)
/* Enabling global STFCF configuration file */
#define MBEDTLS_CONFIG_FILE "mx_stfcf_config.h"
#endif /* CMSIS_USE_Security_STFCF_PSA_API_1_0_0 */

#ifdef __cplusplus
}
#endif


#endif /* PRE_INCLUDE_GLOBAL_H_STMicroelectronics_stfcf */
