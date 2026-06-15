/**
  ******************************************************************************
  * @file    cmac_alt.c
  * @brief   Implementation of mbedtls_alt CMAC module
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
  ******************************************************************************
  */

/**
  *  This file implements STMicroelectronics CMAC with STCryptoLib services on API from mbed TLS
  *
  *  The CMAC Secure Hash Standard was published by NIST.
  *
  * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
  *
  * - RFC 4493 - The AES-CMAC Algorithm
  * https://tools.ietf.org/html/rfc4493
  */

/* Includes ------------------------------------------------------------------*/
#include "mbedtls/cmac.h"
#include "mbedtls/cipher.h"
#include "mbedtls/md.h"

#if defined(MBEDTLS_CMAC_C)
#if defined(MBEDTLS_CMAC_ALT)
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_STCRYPTOLIB_CMAC_ALT)

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/

/* Private macro -------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_CMAC_ALT_FUNCTIONS STCRYPTOLIB CMAC Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief Public API functions for STCRYPTOLIB CMAC alternate implementation.
  * @{
  */

int mbedtls_cipher_cmac_starts(mbedtls_cipher_context_t *ctx, const unsigned char *key, size_t keybits)
{
  cmox_mac_retval_t retval;  /* STCryptoLib return value */
  unsigned int type;
  mbedtls_cmac_context_t *cmac_ctx_int;

  if ((ctx == NULL) || (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) || (key == NULL))
  {
    return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
  }

  /* Allocated and initialise in the cipher context memory for the CMAC context */
  cmac_ctx_int = mbedtls_calloc(1, sizeof(mbedtls_cmac_context_t));
  if (cmac_ctx_int == NULL)
  {
    return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
  }

  ctx->MBEDTLS_PRIVATE(cmac_ctx) = cmac_ctx_int;

  /* Init the STCryptoLib */
  cmox_init_arg_t init_arg;
  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  if (cmox_initialize(&init_arg) != CMOX_INIT_SUCCESS)
  {
    return -1;
  }

  ctx->MBEDTLS_PRIVATE(cmac_ctx)->mac_ctx = cmox_cmac_construct(&ctx->MBEDTLS_PRIVATE(cmac_ctx)->cmac_ctx,
                                                                CMOX_CMAC_AES);

  retval = cmox_mac_init(ctx->MBEDTLS_PRIVATE(cmac_ctx)->mac_ctx);
  if (retval != CMOX_MAC_SUCCESS)
  {
    return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
  }

  retval = cmox_mac_setKey(ctx->MBEDTLS_PRIVATE(cmac_ctx)->mac_ctx, key, keybits / 8U);
  if (retval != CMOX_MAC_SUCCESS)
  {
    return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
  }

  type = ctx->MBEDTLS_PRIVATE(cipher_info)->MBEDTLS_PRIVATE(type);

  switch (type)
  {
    case MBEDTLS_CIPHER_AES_128_ECB:
    case MBEDTLS_CIPHER_AES_192_ECB:
    case MBEDTLS_CIPHER_AES_256_ECB:
      break;
    case MBEDTLS_CIPHER_DES_EDE3_ECB:
      return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
      break;
    default:
      return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
      break;
  }

  return 0;
}

int mbedtls_cipher_cmac_update(mbedtls_cipher_context_t *ctx, const unsigned char *input, size_t ilen)
{
  cmox_mac_retval_t retval;  /* STCryptoLib return value */

  if ((ctx == NULL) || (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) || (input == NULL)
      || (ctx->MBEDTLS_PRIVATE(cmac_ctx) == NULL))
  {
    return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
  }

  retval = cmox_mac_append(ctx->MBEDTLS_PRIVATE(cmac_ctx)->mac_ctx, input, ilen);
  if (retval != CMOX_MAC_SUCCESS)
  {
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  }

  return 0;
}

int mbedtls_cipher_cmac_finish(mbedtls_cipher_context_t *ctx, unsigned char *output)
{
  cmox_mac_retval_t retval;     /* STCryptoLib return value */
  size_t computed_tag_len = 0;  /* Size computed by STCryptoLib */
  size_t expected_tag_len = 16U;

  if ((ctx == NULL) || (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) || (ctx->MBEDTLS_PRIVATE(cmac_ctx) == NULL)
      || (output == NULL))
  {
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  }

  retval = cmox_mac_setTagLen(ctx->MBEDTLS_PRIVATE(cmac_ctx)->mac_ctx, expected_tag_len);
  if (retval != CMOX_MAC_SUCCESS)
  {
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  }

  /* Only generate supported, Verify to do */
  retval = cmox_mac_generateTag(ctx->MBEDTLS_PRIVATE(cmac_ctx)->mac_ctx, output, &computed_tag_len);
  if (retval != CMOX_MAC_SUCCESS)
  {
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  }
  if (computed_tag_len != expected_tag_len)
  {
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
  }

  return 0;
}

int mbedtls_cipher_cmac(const mbedtls_cipher_info_t *cipher_info,  const unsigned char *key, size_t keylen,
                        const unsigned char *input, size_t ilen, unsigned char *output)
{
  mbedtls_cipher_context_t ctx;
  int ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;

  if ((cipher_info == NULL) || (key == NULL) || (input == NULL) || (output == NULL))
  {
    return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
  }

  mbedtls_cipher_init(&ctx);

  ret = mbedtls_cipher_setup(&ctx, cipher_info);
  if (ret != 0)
  {
    goto exit;
  }

  ret = mbedtls_cipher_cmac_starts(&ctx, key, keylen);
  if (ret != 0)
  {
    goto exit;
  }

  ret = mbedtls_cipher_cmac_update(&ctx, input, ilen);
  if (ret != 0)
  {
    goto exit;
  }

  ret = mbedtls_cipher_cmac_finish(&ctx, output);

exit:
  mbedtls_cipher_free(&ctx);

  return ret;
}

#if defined(MBEDTLS_AES_C)
/**
  * @brief Implementation of AES-CMAC-PRF-128 defined in RFC 4615
  */
int mbedtls_aes_cmac_prf_128(const unsigned char *key, size_t key_length,
                             const unsigned char *input, size_t in_len,
                             unsigned char output[16])
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  const mbedtls_cipher_info_t *cipher_info;
  unsigned char zero_key[MBEDTLS_AES_BLOCK_SIZE];
  unsigned char int_key[MBEDTLS_AES_BLOCK_SIZE];

  if ((key == NULL) || (input == NULL) || (output == NULL))
  {
    return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
  }

  cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
  if (cipher_info == NULL)
  {
    /* Failing at this point must be due to a build issue */
    ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    goto exit;
  }

  if (key_length == (size_t)MBEDTLS_AES_BLOCK_SIZE)
  {
    /* Use key as is */
    (void)memcpy(int_key, key, MBEDTLS_AES_BLOCK_SIZE);
  }
  else
  {
    (void)memset(zero_key, 0, MBEDTLS_AES_BLOCK_SIZE);

    ret = mbedtls_cipher_cmac(cipher_info, zero_key, 128, key,
                              key_length, int_key);
    if (ret != 0)
    {
      goto exit;
    }
  }

  ret = mbedtls_cipher_cmac(cipher_info, int_key, 128, input, in_len,
                            output);

exit:
  mbedtls_platform_zeroize(int_key, sizeof(int_key));

  return ret;
}

/**
  * @}
  */

#endif /* MBEDTLS_AES_C */

#endif /* MBEDTLS_STCRYPTOLIB_CMAC_ALT */

#endif /* MBEDTLS_CMAC_ALT*/
#endif /* MBEDTLS_CMAC_C */
