/**
  ******************************************************************************
  * @file    drbg_alt.c
  * @brief   DRBG module to use STM32 Crypto Library as a source of entropy
  *          This file provides Mbed TLS DRBG alternative
  *
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  * Copyright The Mbed TLS Contributors
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  *  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "drbg_alt.h"
#if defined (MBEDTLS_STCRYPTOLIB_DRBG_ALT)

#define RNG_GENERATION_TIMEOUT 10U
#define ENTROPY_SIZE 32
#define NONE_SIZE 16
#define PERSONALIZATION_SIZE 32
/* Global variables ----------------------------------------------------------*/
static uint8_t Entropy[ENTROPY_SIZE] = {0};
static uint8_t Nonce[NONE_SIZE] = {0};
static uint8_t Personalization[PERSONALIZATION_SIZE] = {0};

/* Private typedef -----------------------------------------------------------*/
/* Private defines -----------------------------------------------------------*/
/* Private macros ------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
static uint8_t init_ctx = 0;
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
static cmox_drbg_handle_t *drbg_ctx;         /*!< drbg ctx */
static cmox_ctr_drbg_handle_t ctr_drbg_ctx;  /*!< ctr drbg ctx */
static hal_rng_handle_t *pENTROPY = NULL;
/* Private function prototypes -----------------------------------------------*/
/* Functions Definition ------------------------------------------------------*/

/**
  * @addtogroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_DRBG_ALT_API
  * @{
  */

/**
  * @brief   Initialize the DRBG context and entropy sources.
  * @retval  0 on success, -1 on failure.
  */

int32_t DRBG_Init(void)
{
  uint8_t dummy[4];

  /* Init the StCryptoLib */
  cmox_init_arg_t init_arg;

  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  if (cmox_initialize(&init_arg) != CMOX_INIT_SUCCESS)
  {
    return -1;
  }
  pENTROPY = mx_stfcf_mbedtls_alt_hal_rng_gethandle();

  if (HAL_RNG_GenerateRandomNumber(pENTROPY, (uint32_t *)Entropy, ENTROPY_SIZE / 4, RNG_GENERATION_TIMEOUT) != HAL_OK)
  {
    return -1;

  }

  if (HAL_RNG_GenerateRandomNumber(pENTROPY, (uint32_t *)Nonce, NONE_SIZE / 4, RNG_GENERATION_TIMEOUT) != HAL_OK)
  {
    return -1;
  }

  if (HAL_RNG_GenerateRandomNumber(pENTROPY, (uint32_t *)Personalization, PERSONALIZATION_SIZE / 4,
                                   RNG_GENERATION_TIMEOUT) != HAL_OK)
  {
    return -1;
  }

  drbg_ctx = cmox_ctr_drbg_construct(&ctr_drbg_ctx, CMOX_CTR_DRBG_AES256);

  if (cmox_drbg_init(drbg_ctx, Entropy, sizeof(Entropy), Personalization, sizeof(Personalization),
                     Nonce, sizeof(Nonce)) != CMOX_DRBG_SUCCESS)
  {
    return -1;
  }

  /* first random number generated after setting the DRBG bit must not be used */
  if (cmox_drbg_generate(drbg_ctx, NULL, 0, dummy, 4U) != CMOX_DRBG_SUCCESS)
  {
    return -1;
  }

  return 0;
}

/**
  * @brief   Generate random bytes using DRBG.
  * @param   output         Pointer to buffer to receive random bytes.
  * @param   length         Number of random bytes to generate.
  * @param   output_length  Pointer to variable to receive actual number of bytes generated.
  * @retval  0 on success, -1 on failure.
  */

int32_t DRBG_GetBytes(uint8_t *output, size_t length, size_t *output_length)
{
  int32_t ret = 0;
  uint8_t try = 0;
  uint8_t random[4];
  *output_length = 0;

  /* Get Random byte */
  while ((*output_length < length) && (ret == 0))
  {
    if (cmox_drbg_generate(drbg_ctx, NULL, 0, random, sizeof(random)) != CMOX_DRBG_SUCCESS)
    {
      /* retry when random number generated are not immediately available */
      if (try < 3U)
        {
          try++;
        }
      else
      {
        ret = -1;
      }
    }
    else
    {
      for (uint8_t i = 0; (i < 4U) && (*output_length < length) ; i++)
      {
        *output = random[i];
        output++;
        *output_length += 1U;
        random[i] = 0;
      }
    }
  }

  return ret;
}

/**
  * @brief   Deinitialize the DRBG context.
  * @retval  0 on success, -1 on failure.
  */

int32_t DRBG_DeInit(void)
{
  /* Cleanup the context */
  if (cmox_drbg_cleanup(drbg_ctx) != CMOX_DRBG_SUCCESS)
  {
    return -1;
  }

  return 0;
}

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
/* Interface for PSA crypto API */
psa_status_t mbedtls_psa_external_get_random(
  mbedtls_psa_external_random_context_t *context,
  uint8_t *output, size_t output_size, size_t *output_length)
{
  (void) context;

  if (init_ctx == 0U)
  {
    if (DRBG_Init() != 0)
    {
      return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
    init_ctx = 1U;
  }

  if (DRBG_GetBytes(output, output_size, output_length) != 0)
  {
    return PSA_ERROR_INSUFFICIENT_ENTROPY;
  }
  return PSA_SUCCESS;
}
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
#endif /* MBEDTLS_STCRYPTOLIB_DRBG_ALT */

/**
  * @}
  */
