/**
  ******************************************************************************
  * @file    entropy_hardware_alt.c
  * @brief   Entropy Hardware module to use STM32 RNG Ip as a source of entropy
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
#include "entropy_hardware_alt.h"
#if defined (MBEDTLS_HAL_ENTROPY_HARDWARE_ALT)
#if defined(MBEDTLS_ENTROPY_C)
#include "mbedtls/platform.h"
/* Private define ------------------------------------------------------------*/
#define GENERATION_TIMEOUT_MS      10U  /* The more random data to generate, the longer the timeout */
/* Warning: this timeout value is defined for this example context. */
/* @user: set the timeout value according to the TRNG section of the Reference Manual.*/
#define WORD_SIZE_BYTES             4U  /* STM32 MCU: a word is 4 bytes                             */
#define MAX_RNG_ATTEMPTS            3U  /* Number of attempts in case of failure                    */

/* Private variables ---------------------------------------------------------*/
static hal_rng_handle_t *pENTROPY = NULL;
/* Private functions prototype -----------------------------------------------*/
static void GetRandomBytes(uint8_t *output, size_t req_len, size_t *output_len);


int32_t mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
  uint32_t rng_attempts = 0;
  int32_t return_status = 0;

  /* This parameter is not used in this implementation */
  (void)data; /* prevent "unused variable" warnings */

  *olen = 0;

  while ((rng_attempts < MAX_RNG_ATTEMPTS) && (*olen != len))
  {
    GetRandomBytes(output, len, olen);
    rng_attempts++;
  }

  if (*olen != len)
  {
    return_status = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
  }

  return return_status;
}

/**
  * brief        : Gets random bytes from the STM32 (T)RNG
  * output       : the random bytes returned as an array of uint8_t
  * req_len      : the requested number of random bytes
  * output_len   : the actual number of random bytes in output
  * retval       : None, the caller checks output_len
  */
static void GetRandomBytes(uint8_t *output, const size_t req_len, size_t *output_len)
{
  /* Get the (T)RNG handle for the HAL calls */
  pENTROPY = mx_stfcf_mbedtls_alt_hal_rng_gethandle();

  /** Attention: The (T)RNG produces 32-bit random numbers.
    * This function converts the produced uin32_t numbers into the requested uint8_t format.
    */
  uint8_t *pos_output                      = output;  /* next address in the output buffer to write data */
  uint32_t nb_rand_words                   = 0;
  uint32_t nb_rand_last_bytes              = 0;
  uint8_t random[WORD_SIZE_BYTES] = {0};


  *output_len = 0;

  /*
    * Get 'output length' random byte(s) with the HAL API returning 32-bit random numbers
    * output length = nb_rand_words * WORD_SIZE_BYTES + nb_rand_last_bytes
    */
  nb_rand_words = req_len / WORD_SIZE_BYTES; /* Number of 32-bit words */
  nb_rand_last_bytes = req_len % WORD_SIZE_BYTES; /* number of last bytes */

  /*
    * Get the random numbers
    */
  if (nb_rand_words != 0U)
  {
    /* Draw nb_rand_words 32-bit random numbers */
    if (HAL_RNG_GenerateRandomNumber(pENTROPY,
                                     (uint32_t *)output,
                                     nb_rand_words,
                                     GENERATION_TIMEOUT_MS) == HAL_OK)
    {
      *output_len = nb_rand_words * WORD_SIZE_BYTES;
    }
    /* else: the output_length is not updated, the caller must check this to detect the issue */
    else
    {
      (void)HAL_RNG_RecoverSeedError(pENTROPY);
    }
  }

  if (nb_rand_last_bytes != 0U)
  {
    /* Draw one 32-bit random number and extract nb_rand_last_bytes from it */
    if (HAL_RNG_GenerateRandomNumber(pENTROPY,
                                     (uint32_t *)random,
                                     1U, /* we need one 32-bit random number */
                                     GENERATION_TIMEOUT_MS) == HAL_OK)
    {
      pos_output = output + *output_len; /* next write position: after the nb_rand_words 32-bit random numbers */
      /* Write the nb_rand_last_bytes in 'output' */
      for (uint32_t idx = 0 ; idx < nb_rand_last_bytes ; idx++)
      {
        *pos_output = random[idx];
        pos_output++;
      }

      *output_len = *output_len + nb_rand_last_bytes;
    }
    /* else: the output_length is not updated, the caller must check this to detect the issue */
    else
    {
      (void)HAL_RNG_RecoverSeedError(pENTROPY);
    }
  }
}
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_HAL_ENTROPY_HARDWARE_ALT */
