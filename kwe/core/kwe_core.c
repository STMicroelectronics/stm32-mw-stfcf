/**
  ******************************************************************************
  * @file    kwe_core.c
  * @brief   Implementation of STM32 KWE Middleware Core module
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

/* Includes ------------------------------------------------------------------*/
#include "kwe_core.h"
#include <string.h>
#include <stdlib.h>
#include "mx_hal_def.h"
/** @defgroup KWE_MODULES KWE MODULES
  * @{
  */

/** @defgroup KWE_CORE KWE CORE
  * @{
  */
#if defined(KWE_DRIVER_ENABLED)
/* Global variables ----------------------------------------------------------*/
/** @defgroup KWE_CORE_Exported_Variables KWE Core Exported Variables
  * @{
  */
#if defined(KWE_ASYMMETRIC_KEY_WRAP_ENABLED)
/**
  * CCB handler to set CCB
  */
static hal_ccb_handle_t *pCCB = NULL;
#endif /* KWE_ASYMMETRIC_KEY_WRAP_ENABLED */

#if defined(KWE_SYMMETRIC_KEY_WRAP_ENABLED)
/**
  * AES/CRYP handler to set SAES
  */
static hal_aes_handle_t *pSAES = NULL;
#endif /* KWE_SYMMETRIC_KEY_WRAP_ENABLED */

#if defined(USE_HAL_AES_CCM_ALGO) && (USE_HAL_AES_CCM_ALGO == 1)
static hal_aes_gcm_config_t conf_gcm = {0};
static hal_aes_ccm_config_t conf_ccm = {0};
#endif /* USE_HAL_AES_CCM_ALGO */

/**
  * @}
  */

/* Private variables ---------------------------------------------------------*/
#if defined(KWE_ASYMMETRIC_KEY_WRAP_ENABLED)
static uint8_t pool_buffer[512] = {0};
#endif /* KWE_ASYMMETRIC_KEY_WRAP_ENABLED */

/* Private typedef -----------------------------------------------------------*/
/* Private macros ------------------------------------------------------------*/
/** @defgroup KWE_CORE_Private_Macros KWE Core Private Macros
  * @{
  */

/**
  * 32-bit integer manipulation macros (big endian)
  */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                         \
  do {                                               \
    (n) = ((uint32_t) (b)[(i)    ] << 24 ) |         \
          ((uint32_t) (b)[(i) + 1U] << 16 ) |        \
          ((uint32_t) (b)[(i) + 2U] <<  8 ) |        \
          ((uint32_t) (b)[(i) + 3U]       );         \
  } while(0)
#endif /* !GET_UINT32_BE */
/**
  * @}
  */

/* Private defines -----------------------------------------------------------*/
/** @defgroup KWE_CORE_Private_Constants KWE Core Private Constants
  * @{
  */
#define KWE_TIMEOUT_VALUE     (0xFFF)
#define KWE_IV_MAX_SIZE       (16U)
#define KWE_BLOB_IV_OFFSET    0x00000000
#define KWE_BLOB_TAG_OFFSET   0x00000004
#define KWE_BLOB_KEY_OFFSET   0x00000008

/**
  * @}
  */

/* Private function prototypes -----------------------------------------------*/
/* Functions Definition ------------------------------------------------------*/
/** @defgroup KWE_CORE_Exported_Functions KWE Core Exported Functions
  * @{
  */

/** @defgroup KWE_CORE_Exported_Functions_Group1 Key Wrap functions
  *  @brief    KWE APIs related to Key Wrap Operations.
  *
@verbatim
 ===============================================================================
              ##### Key Wrap functions #####
 ===============================================================================
[..]
    (+) GenerateWrappedEccKey
    (+) WrapEccKey
    (+) RsaKeyWrap

@endverbatim
  * @{
  */

#if defined(KWE_ASYMMETRIC_KEY_WRAP_ENABLED)
/**
  * @brief  A function that generates ECC private key in wrapped form using
  *         KWE hardware accelerator.
  * @param  p_ecp : pointer to elliptic curve parameters.
  * @param  ecc_alg : elliptic curve algorithm takes value
  *         KWE_ALG_ECC_ECDSA or KWE_ALG_ECC_ECDH.
  * @param  p_key_buffer : a pointer to be filled with the wrapped key, IV,
  *         and the tag associate to the wrapped key.
  * @param  key_buffer_size : size of the key in bytes.
  * @param  p_key_buffer_length : a pointer to the size of the wrapped key in
  *         bytes.
  * @note   The key generated can be used for ECC digital signature or
  *         ECC ECDH key exchange.
  * @retval KWE_SUCCESS if success, an error code otherwise.
  */
kwe_status_t KWE_EccGenerateWrappedKey(
  kwe_ecp_t *p_ecp,
  kwe_algorithm_t ecc_alg,
  uint8_t *p_key_buffer,
  size_t key_buffer_size,
  size_t *p_key_buffer_length)
{
  pCCB = mx_stfcf_kwe_ccb_gethandle();
  kwe_status_t status = KWE_ERROR;
  hal_ccb_ecdsa_curve_param_t ecdsa_param;
  hal_ccb_ecdsa_key_blob_t ecdsa_key_blob;
  hal_ccb_ecc_mul_curve_param_t ecdh_param;
  hal_ccb_ecc_mul_key_blob_t ecdh_blob;

  if (ecc_alg == KWE_ALG_ECC_ECDSA)
  {
    ecdsa_param.prime_order_size_byte            = p_ecp->order_size;
    ecdsa_param.modulus_size_byte                = p_ecp->modulus_size;
    ecdsa_param.p_modulus                        = p_ecp->p_prime;
    ecdsa_param.coef_sign_a                      = p_ecp->a_sign;
    ecdsa_param.p_abs_coef_a                     = p_ecp->p_a_abs;
    ecdsa_param.p_coef_b                         = p_ecp->p_b;
    ecdsa_param.p_point_x                        = p_ecp->p_gx;
    ecdsa_param.p_point_y                        = p_ecp->p_gy;
    ecdsa_param.p_prime_order                    = p_ecp->p_n;
    ecdsa_param.ecdsa_pool_buffer.p_buff         = pool_buffer;
    ecdsa_param.ecdsa_pool_buffer.buff_size_byte = HAL_CCB_ECDSA_CALC_BUFFER_SIZE(ecdsa_param.modulus_size_byte);

    ecdsa_key_blob.p_iv          = (uint32_t *)p_key_buffer + KWE_BLOB_IV_OFFSET;
    ecdsa_key_blob.p_tag         = (uint32_t *)p_key_buffer + KWE_BLOB_TAG_OFFSET;
    ecdsa_key_blob.p_wrapped_key = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET;

    if (HAL_CCB_ECDSA_HW_GenerateWrapPrivateKey(pCCB, &ecdsa_param, HAL_CCB_KEY_HW, &ecdsa_key_blob) != HAL_OK)
    {
      return status;
    }
  }
  else if (ecc_alg == KWE_ALG_ECC_ECDH)
  {
    ecdh_param.prime_order_size_byte            = p_ecp->order_size;
    ecdh_param.modulus_size_byte                = p_ecp->modulus_size;
    ecdh_param.p_modulus                        = p_ecp->p_prime;
    ecdh_param.coef_sign_a                      = p_ecp->a_sign;
    ecdh_param.p_abs_coef_a                     = p_ecp->p_a_abs;
    ecdh_param.p_coef_b                         = p_ecp->p_b;
    ecdh_param.p_point_x                        = p_ecp->p_gx;
    ecdh_param.p_point_y                        = p_ecp->p_gy;
    ecdh_param.p_prime_order                    = p_ecp->p_n;
    ecdh_param.ecc_pool_buffer.p_buff           = pool_buffer;
    ecdh_param.ecc_pool_buffer.buff_size_byte   = HAL_CCB_ECC_CALC_BUFFER_SIZE(ecdh_param.modulus_size_byte);

    ecdh_blob.p_iv          = (uint32_t *)p_key_buffer + KWE_BLOB_IV_OFFSET;
    ecdh_blob.p_tag         = (uint32_t *)p_key_buffer + KWE_BLOB_TAG_OFFSET;
    ecdh_blob.p_wrapped_key = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET;

    if (HAL_CCB_ECC_HW_GenerateWrapPrivateKey(pCCB, &ecdh_param, HAL_CCB_KEY_HW, &ecdh_blob) != HAL_OK)
    {
      return status;
    }
  }
  else
  {
    return KWE_ERROR_NOT_SUPPORTED;
  }

  *p_key_buffer_length = key_buffer_size;

  status = KWE_SUCCESS;

  return status;
}

/**
  * @brief  A function that wrap ECC private key using KWE hardware
  *         accelerator.
  * @param  p_ecp : a pointer to elliptic curve parameters.
  * @param  ecc_alg : elliptic curve algorithm takes value
  *         KWE_ALG_ECC_ECDSA or KWE_ALG_ECC_ECDH.
  * @param  p_data : a pointer to the transparent key to be wrapped.
  * @param  p_key_buffer : a pointer to buffer to be filled with the wrapped key,
  *         IV, and the tag associate to the wrapped key.
  * @param  key_buffer_size : size of the key buffer in bytes.
  * @param  p_key_buffer_length : a pointer to the actual size of the wrapped
  *         key in bytes.
  * @note   The wrapped key can be used for ECC digital signature or
  *         ECC ECDH key exchange.
  * @retval KWE_SUCCESS if success, an error code otherwise.
  */
kwe_status_t KWE_EccWrapKey(
  kwe_ecp_t *p_ecp,
  kwe_algorithm_t ecc_alg,
  const uint8_t *p_data,
  uint8_t *p_key_buffer,
  size_t key_buffer_size,
  size_t *p_key_buffer_length)
{
  pCCB = mx_stfcf_kwe_ccb_gethandle();
  kwe_status_t status = KWE_ERROR;
  hal_ccb_ecdsa_curve_param_t ecdsa_param;
  hal_ccb_ecdsa_key_blob_t ecdsa_key_blob;
  hal_ccb_ecc_mul_curve_param_t ecdh_param;
  hal_ccb_ecc_mul_key_blob_t ecdh_blob;
  const uint8_t *p_key_data = p_data;

  if (ecc_alg == KWE_ALG_ECC_ECDSA)
  {
    /* Fill ECDSA In parameters */
    ecdsa_param.prime_order_size_byte            = p_ecp->order_size;
    ecdsa_param.modulus_size_byte                = p_ecp->modulus_size;
    ecdsa_param.p_modulus                        = p_ecp->p_prime;
    ecdsa_param.coef_sign_a                      = p_ecp->a_sign;
    ecdsa_param.p_abs_coef_a                     = p_ecp->p_a_abs;
    ecdsa_param.p_coef_b                         = p_ecp->p_b;
    ecdsa_param.p_point_x                        = p_ecp->p_gx;
    ecdsa_param.p_point_y                        = p_ecp->p_gy;
    ecdsa_param.p_prime_order                    = p_ecp->p_n;
    ecdsa_param.ecdsa_pool_buffer.p_buff         = pool_buffer;
    ecdsa_param.ecdsa_pool_buffer.buff_size_byte = HAL_CCB_ECDSA_CALC_BUFFER_SIZE(ecdsa_param.modulus_size_byte);

    ecdsa_key_blob.p_iv          = (uint32_t *)p_key_buffer + KWE_BLOB_IV_OFFSET;
    ecdsa_key_blob.p_tag         = (uint32_t *)p_key_buffer + KWE_BLOB_TAG_OFFSET;
    ecdsa_key_blob.p_wrapped_key = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET;

    if (HAL_CCB_ECDSA_HW_WrapPrivateKey(pCCB, &ecdsa_param, p_key_data, HAL_CCB_KEY_HW, &ecdsa_key_blob) != HAL_OK)
    {
      return status;
    }
  }
  else if (ecc_alg == KWE_ALG_ECC_ECDH)
  {
    ecdh_param.prime_order_size_byte            = p_ecp->order_size;
    ecdh_param.modulus_size_byte                = p_ecp->modulus_size;
    ecdh_param.p_modulus                        = p_ecp->p_prime;
    ecdh_param.coef_sign_a                      = p_ecp->a_sign;
    ecdh_param.p_abs_coef_a                     = p_ecp->p_a_abs;
    ecdh_param.p_coef_b                         = p_ecp->p_b;
    ecdh_param.p_point_x                        = p_ecp->p_gx;
    ecdh_param.p_point_y                        = p_ecp->p_gy;
    ecdh_param.p_prime_order                    = p_ecp->p_n;
    ecdh_param.ecc_pool_buffer.p_buff           = pool_buffer;
    ecdh_param.ecc_pool_buffer.buff_size_byte   = HAL_CCB_ECC_CALC_BUFFER_SIZE(ecdh_param.modulus_size_byte);

    ecdh_blob.p_iv          = (uint32_t *)p_key_buffer + KWE_BLOB_IV_OFFSET;
    ecdh_blob.p_tag         = (uint32_t *)p_key_buffer + KWE_BLOB_TAG_OFFSET;
    ecdh_blob.p_wrapped_key = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET;

    if (HAL_CCB_ECC_HW_WrapPrivateKey(pCCB, &ecdh_param, p_key_data, HAL_CCB_KEY_HW, &ecdh_blob) != HAL_OK)
    {
      return status;
    }
  }
  else
  {
    return KWE_ERROR_NOT_SUPPORTED;
  }

  *p_key_buffer_length = key_buffer_size;

  status = KWE_SUCCESS;

  return status;
}

/**
  * @brief  A function that can wrap RSA private key (Exponent and phi
  *         parameters) using KWE hardware accelerator.
  * @param  p_rsa : a pointer to RSA parameters.
  * @param  p_key_buffer : a pointer to buffer where the wrapped private
  *         key is to be written.
  * @param  p_key_buffer_length : a pointer to the actual size of outputted
  *         wrapped private key in bytes.
  * @retval KWE_SUCCESS if success, an error code otherwise
  */
kwe_status_t KWE_RsaWrapKey(
  kwe_rsa_t *p_rsa,
  uint8_t *p_key_buffer,
  size_t *p_key_buffer_length)
{
  pCCB = mx_stfcf_kwe_ccb_gethandle();
  kwe_status_t status = KWE_ERROR;
  uint32_t *p_modulus = NULL;
  hal_ccb_rsa_param_t rsa_mod_exp_param;
  hal_ccb_rsa_key_blob_t rsa_mod_exp_blob;
  hal_ccb_rsa_clear_key_t rsa_key;

  /* Fill RSA Modular exponentiation In parameters */
  rsa_mod_exp_param.exp_size_byte     = p_rsa->exponent_size;
  rsa_mod_exp_param.modulus_size_byte = p_rsa->modulus_size;
  rsa_mod_exp_param.p_mod             = p_rsa->p_modulus;
  rsa_mod_exp_param.rsa_pool_buffer.p_buff         = pool_buffer;
  rsa_mod_exp_param.rsa_pool_buffer.buff_size_byte = HAL_CCB_RSA_CALC_BUFFER_SIZE(rsa_mod_exp_param.modulus_size_byte);

  rsa_key.p_exp = p_rsa->p_exponent;
  rsa_key.p_phi = p_rsa->p_phi;

  /* Prepare RSA Modular exponentiation parameters  */
  rsa_mod_exp_blob.p_iv          = (uint32_t *)p_key_buffer + KWE_BLOB_IV_OFFSET;
  rsa_mod_exp_blob.p_tag         = (uint32_t *)p_key_buffer + KWE_BLOB_TAG_OFFSET;
  rsa_mod_exp_blob.p_wrapped_exp = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET;
  rsa_mod_exp_blob.p_wrapped_phi = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET
                                   + (rsa_mod_exp_param.exp_size_byte / 4U);

  if (HAL_CCB_RSA_HW_WrapPrivateKey(pCCB, &rsa_mod_exp_param, &rsa_key, HAL_CCB_KEY_HW, &rsa_mod_exp_blob) != HAL_OK)
  {
    return status;
  }

  p_modulus = rsa_mod_exp_blob.p_wrapped_phi + (rsa_mod_exp_param.modulus_size_byte / 4U);

  (void) memcpy((uint8_t *)p_modulus, (const uint8_t *)rsa_mod_exp_param.p_mod, rsa_mod_exp_param.modulus_size_byte);

  *p_key_buffer_length = (rsa_mod_exp_param.modulus_size_byte + rsa_mod_exp_param.exp_size_byte
                          + p_rsa->phi_size + (4U * sizeof(rsa_mod_exp_blob.p_iv))
                          + (4U * sizeof(rsa_mod_exp_blob.p_tag)));


  status = KWE_SUCCESS;

  return status;
}

/**
  * @}
  */

/** @defgroup KWE_CORE_Exported_Functions_Group2 Asymmetric Key functions
  *  @brief    KWE APIs related to Asymmetric Key Operations.
  *
@verbatim
 ===============================================================================
              ##### Asymmetric Key functions #####
 ===============================================================================
[..]  This section provides functions allowing:
    (+) EcdsaPublicKeyExport
    (+) EcdhKeyAgreement

@endverbatim
  * @{
  */

/**
  * @brief  A function that export ECDSA public key from wrapped ECDSA
  *         private key through KWE hardware accelerator.
  * @param  p_ecp : a pointer to elliptic curve parameters.
  * @param  p_key_buffer : a pointer to the wrapped ECDSA private key.
  * @param  p_public_key : a pointer to buffer where the public key data is
  *         to be written.
  * @param  public_key_size : Size of the public_key buffer in bytes.
  * @param  p_public_key_length : a pointer to the actual size of outputted
  *         public key in bytes.
  * @retval KWE_SUCCESS if success, an error code otherwise
  */
kwe_status_t KWE_EcdsaPublicKeyExport(
  kwe_ecp_t *p_ecp,
  const uint8_t *p_key_buffer,
  uint8_t *p_public_key,
  size_t public_key_size,
  size_t *p_public_key_length)
{
  pCCB = mx_stfcf_kwe_ccb_gethandle();
  kwe_status_t status = KWE_ERROR;
  hal_ccb_ecdsa_curve_param_t ecdsa_param;
  hal_ccb_ecdsa_key_blob_t ecdsa_key_blob;
  hal_ccb_ecc_point_t public_key_out;

  ecdsa_param.prime_order_size_byte            = p_ecp->order_size;
  ecdsa_param.modulus_size_byte                = p_ecp->modulus_size;
  ecdsa_param.p_modulus                        = p_ecp->p_prime;
  ecdsa_param.coef_sign_a                      = p_ecp->a_sign;
  ecdsa_param.p_abs_coef_a                     = p_ecp->p_a_abs;
  ecdsa_param.p_coef_b                         = p_ecp->p_b;
  ecdsa_param.p_point_x                        = p_ecp->p_gx;
  ecdsa_param.p_point_y                        = p_ecp->p_gy;
  ecdsa_param.p_prime_order                    = p_ecp->p_n;
  ecdsa_param.ecdsa_pool_buffer.p_buff         = pool_buffer;
  ecdsa_param.ecdsa_pool_buffer.buff_size_byte = HAL_CCB_ECDSA_CALC_BUFFER_SIZE(ecdsa_param.modulus_size_byte);

  ecdsa_key_blob.p_iv          = (uint32_t *)p_key_buffer + KWE_BLOB_IV_OFFSET;
  ecdsa_key_blob.p_tag         = (uint32_t *)p_key_buffer + KWE_BLOB_TAG_OFFSET;
  ecdsa_key_blob.p_wrapped_key = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET;

#if defined(KWE_ECP_SHORT_WEIERSTRASS_ENABLED)
  *p_public_key_length = 1U + (2U * ecdsa_param.prime_order_size_byte);

  if (public_key_size < *p_public_key_length)
  {
    return status;
  }

  p_public_key[0] = 0x04;
  public_key_out.p_point_x = p_public_key + 1;
  public_key_out.p_point_y = p_public_key + 1 + (public_key_size / 2U);

#else /* To Do */
  *p_public_key_length = ecdsa_param.prime_order_size_byte;
  public_key_out.p_point_x = p_public_key;
#endif /* KWE_ECP_SHORT_WEIERSTRASS_ENABLED */

  if (HAL_CCB_ECDSA_HW_ComputePublicKey(pCCB, &ecdsa_param, HAL_CCB_KEY_HW, &ecdsa_key_blob, &public_key_out) != HAL_OK)
  {
    return status;
  }

  status = KWE_SUCCESS;

  return status;
}

/**
  * @brief  A function that performs key agreement using an asymmetric
  *         wrapped private key through KWE hardware accelerator
  *         and a peer public key.
  * @param  p_ecp : a pointer to elliptic curve parameters.
  * @param  p_key_buffer : a pointer to the wrapped ECDH private key.
  * @param  p_peer_key : a pointer to the peer public key.
  * @param  peer_key_length : size of the peer public key in bytes.
  * @param  p_shared_secret : a pointer to buffer where the shared secret
  *         data is to be written.
  * @param  shared_secret_size : Size of shared secret buffer in bytes.
  * @param  p_shared_secret_length : a pointer to the actual size of outputted
  *         shared secret in bytes.
  * @retval KWE_SUCCESS if success, an error code otherwise
  */
kwe_status_t KWE_EcdhKeyAgreement(
  kwe_ecp_t *p_ecp,
  const uint8_t *p_key_buffer,
  const uint8_t *p_peer_key,
  size_t peer_key_length,
  uint8_t *p_shared_secret,
  size_t shared_secret_size,
  size_t *p_shared_secret_length)
{
  pCCB = mx_stfcf_kwe_ccb_gethandle();
  kwe_status_t status = KWE_ERROR;
  (void) shared_secret_size;
  hal_ccb_ecc_mul_curve_param_t ecdh_param;
  hal_ccb_ecc_mul_key_blob_t ecdh_blob;
  hal_ccb_ecc_point_t ecdh_peer_pubkey;
  hal_ccb_ecc_point_t ecdh_shared_secret;

  /* Fill ECDSA In parameters */
  ecdh_param.prime_order_size_byte            = p_ecp->order_size;
  ecdh_param.modulus_size_byte                = p_ecp->modulus_size;
  ecdh_param.p_modulus                        = p_ecp->p_prime;
  ecdh_param.coef_sign_a                      = p_ecp->a_sign;
  ecdh_param.p_abs_coef_a                     = p_ecp->p_a_abs;
  ecdh_param.p_coef_b                         = p_ecp->p_b;
  ecdh_param.p_prime_order                    = p_ecp->p_n;
  ecdh_param.ecc_pool_buffer.p_buff           = pool_buffer;
  ecdh_param.ecc_pool_buffer.buff_size_byte   = HAL_CCB_ECC_CALC_BUFFER_SIZE(ecdh_param.modulus_size_byte);

  ecdh_peer_pubkey.p_point_x = (uint8_t *)p_peer_key + 1U;
  ecdh_peer_pubkey.p_point_y = (uint8_t *)p_peer_key + (size_t)1U + (size_t)(peer_key_length / 2U);

  ecdh_blob.p_iv          = (uint32_t *)p_key_buffer + KWE_BLOB_IV_OFFSET;
  ecdh_blob.p_tag         = (uint32_t *)p_key_buffer + KWE_BLOB_TAG_OFFSET;
  ecdh_blob.p_wrapped_key = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET;

  ecdh_shared_secret.p_point_x  = p_shared_secret;
  ecdh_shared_secret.p_point_y  = p_shared_secret + ecdh_param.prime_order_size_byte;

  if (HAL_CCB_ECC_HW_ComputeScalarMul(pCCB, &ecdh_param, HAL_CCB_KEY_HW,
                                      &ecdh_blob, &ecdh_peer_pubkey,
                                      &ecdh_shared_secret) != HAL_OK)
  {
    return status;
  }

  *p_shared_secret_length = (2U * ecdh_param.prime_order_size_byte);

  status = KWE_SUCCESS;

  return status;
}

/**
  * @}
  */

/** @defgroup KWE_CORE_Exported_Functions_Group3 Asymmetric Cryptography functions
  *  @brief    KWE APIs related to Asymmetric Cryptography functions.
  *
@verbatim
 ===============================================================================
              ##### Asymmetric Cryptography functions #####
 ===============================================================================
    [..]
        (+) EcdsaSignHash
        (+) RsaModularExp

@endverbatim
  * @{
  */

/**
  * @brief  A function that sign a hash using an asymmetric
  *         wrapped private key through KWE hardware accelerator.
  * @param  p_ecp : a pointer to elliptic curve parameters.
  * @param  p_key_buffer : a pointer to the wrapped ECC private key.
  * @param  p_hash : pointer to the hash to be signed.
  * @param  p_signature : pointer to signature buffer to store signature.
  * @param  signature_size : size of signature buffer in bytes.
  * @param  p_signature_length : a pointer to the actual size of outputted
  *         signature in bytes.
  * @retval KWE_SUCCESS if success, an error code otherwise
  */
kwe_status_t KWE_EcdsaSignHash(
  kwe_ecp_t *p_ecp,
  const uint8_t *p_key_buffer,
  const uint8_t *p_hash,
  uint8_t hash_length,
  uint8_t *p_signature,
  size_t signature_size,
  size_t *p_signature_length)
{
  pCCB = mx_stfcf_kwe_ccb_gethandle();
  kwe_status_t status = KWE_ERROR;
  uint8_t *p_hash_tmp = (uint8_t *)p_hash;

  hal_ccb_ecdsa_curve_param_t ecdsa_param;
  hal_ccb_ecdsa_key_blob_t ecdsa_key_blob;
  hal_ccb_ecdsa_sign_t ecdsa_result;

  ecdsa_param.prime_order_size_byte = p_ecp->order_size;
  ecdsa_param.modulus_size_byte     = p_ecp->modulus_size;
  ecdsa_param.p_modulus             = p_ecp->p_prime;
  ecdsa_param.coef_sign_a           = p_ecp->a_sign;
  ecdsa_param.p_abs_coef_a          = p_ecp->p_a_abs;
  ecdsa_param.p_coef_b              = p_ecp->p_b;
  ecdsa_param.p_point_x             = p_ecp->p_gx;
  ecdsa_param.p_point_y             = p_ecp->p_gy;
  ecdsa_param.p_prime_order         = p_ecp->p_n;
  ecdsa_param.ecdsa_pool_buffer.p_buff         = pool_buffer;
  ecdsa_param.ecdsa_pool_buffer.buff_size_byte = HAL_CCB_ECDSA_CALC_BUFFER_SIZE(ecdsa_param.modulus_size_byte);

  ecdsa_key_blob.p_iv          = (uint32_t *)p_key_buffer + KWE_BLOB_IV_OFFSET;
  ecdsa_key_blob.p_tag         = (uint32_t *)p_key_buffer + KWE_BLOB_TAG_OFFSET;
  ecdsa_key_blob.p_wrapped_key = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET;

  ecdsa_result.p_r_sign                      = p_signature;
  ecdsa_result.p_s_sign                      = p_signature + (signature_size / 2U);

  if (HAL_CCB_ECDSA_HW_Sign(pCCB, &ecdsa_param, HAL_CCB_KEY_HW, &ecdsa_key_blob,
                            p_hash_tmp, hash_length,
                            &ecdsa_result) != HAL_OK)
  {
    return status;
  }

  *p_signature_length = 2U * ecdsa_param.prime_order_size_byte;

  status = KWE_SUCCESS;

  return status;
}

/**
  * @brief  A function that performs modular exponentiation using wrapped RSA
  *         private key (Exponent and phi) through KWE hardware
  *         accelerator.
  * @param  p_rsa : a pointer to RSA parameters.
  * @param  p_key_buffer : a pointer to wrapped RSA private key.
  * @param  p_input : a pointer to the operand.
  * @param  p_output : a pointer to buffer where the modular exponentiation
  *         result is to be written
  * @retval KWE_SUCCESS if success, an error code otherwise
  */
kwe_status_t KWE_RsaModularExp(
  kwe_rsa_t *p_rsa,
  const uint8_t *p_key_buffer,
  const uint8_t *p_input,
  uint8_t *p_output)
{
  pCCB = mx_stfcf_kwe_ccb_gethandle();
  kwe_status_t status = KWE_ERROR;

  hal_ccb_rsa_param_t rsa_mod_exp_param;
  hal_ccb_rsa_key_blob_t rsa_mod_exp_blob;

  /* Fill RSA Modular exponentiation In parameters */
  rsa_mod_exp_param.exp_size_byte     = p_rsa->exponent_size;
  rsa_mod_exp_param.modulus_size_byte = p_rsa->modulus_size;
  rsa_mod_exp_param.p_mod             = (uint8_t *)p_key_buffer + ((uint32_t)KWE_BLOB_KEY_OFFSET * 4U)
                                        + (2U * rsa_mod_exp_param.modulus_size_byte);

  rsa_mod_exp_param.rsa_pool_buffer.p_buff         = pool_buffer;
  rsa_mod_exp_param.rsa_pool_buffer.buff_size_byte = HAL_CCB_RSA_CALC_BUFFER_SIZE(rsa_mod_exp_param.modulus_size_byte);

  /* Prepare RSA Modular exponentiation parameters  */
  rsa_mod_exp_blob.p_iv          = (uint32_t *)p_key_buffer + KWE_BLOB_IV_OFFSET;
  rsa_mod_exp_blob.p_tag         = (uint32_t *)p_key_buffer + KWE_BLOB_TAG_OFFSET;
  rsa_mod_exp_blob.p_wrapped_exp = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET;
  rsa_mod_exp_blob.p_wrapped_phi = (uint32_t *)p_key_buffer + KWE_BLOB_KEY_OFFSET
                                   + (rsa_mod_exp_param.exp_size_byte / 4U);

  if (HAL_CCB_RSA_HW_ComputeModularExp(pCCB, &rsa_mod_exp_param,
                                       HAL_CCB_KEY_HW, &rsa_mod_exp_blob,
                                       (uint8_t *)p_input, p_output) != HAL_OK)
  {
    return status;
  }

  status = KWE_SUCCESS;

  return status;
}
#endif /* KWE_ASYMMETRIC_KEY_WRAP_ENABLED */

/**
  * @}
  */

/** @defgroup KWE_CORE_Exported_Functions_Group4 Symmetric Cryptography functions
  *  @brief    KWE APIs related to Symmetric Cryptography functions.
  *
@verbatim
 ===============================================================================
              ##### Symmetric Cryptography functions #####
 ===============================================================================
[..]
    (+) WrapAESKey
    (+) AesAeadEncrypt
    (+) AesAeadDecrypt
    (+) AesEncrypt
    (+) AesDecrypt

@endverbatim
  * @{
  */

/**
  * KWE AES hardware engine is Compliant with NIST FIPS
  * publication 197 "Advanced encryption standard (AES)"
  * (November 2001)
  */
#if defined(KWE_SYMMETRIC_KEY_WRAP_ENABLED)
/**
  * @brief  A function that wrap AES key using KWE hardware
  *         accelerator.
  * @param  p_data : a pointer to the transparent key to be wrapped.
  * @param  data_length : size of the transparent key in bytes.
  * @param  p_key_buffer : a pointer to be filled with the wrapped key, IV,
  *         and the tag associate to the wrapped key.
  * @param  key_buffer_size : size of the key in bytes.
  * @param  p_key_buffer_length : a pointer to the size of the wrapped key IV,
  *         and the tag associate to the wrapped key in bytes.
  * @note   The wrapped key can be used for AES and AES AEAD encryption or
  *         decryption operations.
  * @retval KWE_SUCCESS if success, an error code otherwise.
  */
kwe_status_t KWE_WrapKey(
  const uint8_t *p_data,
  size_t data_length,
  uint8_t *p_key_buffer,
  size_t key_buffer_size,
  size_t *p_key_buffer_length)
{
  kwe_status_t status = KWE_ERROR;
  uint32_t key_le[8] = {0};
  uint32_t *p_key = NULL;
  uint32_t i = 0;
  hal_aes_key_size_t aes_key_size;

  if (((key_buffer_size) % 16U) != 0U)
  {
    return status;
  }

  /* Get SAES initialised hundler */
  pSAES = mx_stfcf_kwe_saes_gethandle();

#if defined (KWE_USE_CBC_TO_WRAP_SYMMETRIC_KEY)
  p_key = (uint32_t *)(p_key_buffer + KWE_IV_MAX_SIZE);
  HAL_AES_CBC_SetConfig(pSAES, (uint32_t *)p_key_buffer);
#else
  p_key = (uint32_t *)p_key_buffer;
  if (HAL_AES_ECB_SetConfig(pSAES) != HAL_OK)
  {
    return status;
  }
#endif  /* KWE_USE_CBC_TO_WRAP_SYMMETRIC_KEY */

#if defined(AES_CR_KEYPROT)
  /* Prevent SAES key from being accessed by another security context */
  if (HAL_AES_EnableKeyProtection(pSAES) != HAL_OK)
  {
    return status;
  }
#endif /* AES_CR_KEYPROT */

  if (data_length == 16U)
  {
    aes_key_size = HAL_AES_KEY_SIZE_128BIT;
  }
  else if (data_length == 32U)
  {
    aes_key_size = HAL_AES_KEY_SIZE_256BIT;
  }
  else
  {
    return KWE_ERROR_NOT_SUPPORTED;
  }
  if (HAL_AES_SetHWKey(pSAES, aes_key_size, HAL_AES_KEY_SELECT_DHUK, HAL_AES_KEY_MODE_WRAPPED) != HAL_OK)
  {
    /* Processing Error */
    return status;
  }

  if (HAL_AES_SetDataSwapping(pSAES, HAL_AES_DATA_SWAPPING_NO) != HAL_OK)
  {
    return status;
  }
  /* Set key data in Little endian format */
  for (i = 0; i < (data_length / 4U); i++)
  {
    GET_UINT32_BE(key_le[i], p_data, 4U * i);
  }

  if (HAL_AES_WrapKey(pSAES, key_le, aes_key_size, p_key, KWE_TIMEOUT_VALUE) != HAL_OK)
  {
    /* Processing Error */
    return status;
  }

  *p_key_buffer_length = key_buffer_size;

  status = KWE_SUCCESS;

  return status;
}

/**
  * @brief  A function that unwrap AES key using KWE hardware
  *         accelerator.
  * @param  p_key_buffer : a pointer to the wrapped key and IV associate to
  *         the wrapped key.
  * @param  key_buffer_size : size of the wrapped key and IV in bytes.
  * @note   The unwrapped key can be used for AES and AES AEAD encryption or
  *         decryption operations.
  * @retval KWE_SUCCESS if success, an error code otherwise.
  */
static kwe_status_t KWE_AES_UnwrapKey(
  const uint8_t *p_key_buffer,
  size_t key_buffer_size)
{
  pSAES = mx_stfcf_kwe_saes_gethandle();
  kwe_status_t status = KWE_ERROR;
  uint32_t *p_key = NULL;
  size_t key_size = 0U;
  hal_aes_key_size_t aes_key_size;

#if defined (KWE_USE_CBC_TO_WRAP_SYMMETRIC_KEY)
  key_size = key_buffer_size - KWE_IV_MAX_SIZE;
#else
  key_size = key_buffer_size;
#endif  /* KWE_USE_CBC_TO_WRAP_SYMMETRIC_KEY */
  if (((key_size) % 16U) != 0U)
  {
    return status;
  }
  if (key_size == 16U)
  {
    aes_key_size = HAL_AES_KEY_SIZE_128BIT;
  }
  else if (key_size == 32U)
  {
    aes_key_size = HAL_AES_KEY_SIZE_256BIT;
  }
  else
  {
    return KWE_ERROR_NOT_SUPPORTED;
  }
  /* Configure the AES */
#if defined (KWE_USE_CBC_TO_WRAP_SYMMETRIC_KEY)
  p_key = (uint32_t *)(p_key_buffer + KWE_IV_MAX_SIZE);
  HAL_AES_CBC_SetConfig(pSAES, (uint32_t *)p_key_buffer);
#else
  p_key = (uint32_t *)p_key_buffer;
  if (HAL_AES_ECB_SetConfig(pSAES) != HAL_OK)
  {
    return status;
  }
#endif  /* KWE_USE_CBC_TO_WRAP_SYMMETRIC_KEY */

#if defined(AES_CR_KEYPROT)
  /* Prevent SAES key from being accessed by another security context */
  if (HAL_AES_EnableKeyProtection(pSAES) != HAL_OK)
  {
    return status;
  }
#endif /* AES_CR_KEYPROT */

  if (HAL_AES_SetHWKey(pSAES, aes_key_size, HAL_AES_KEY_SELECT_DHUK, HAL_AES_KEY_MODE_WRAPPED) != HAL_OK)
  {
    /* Processing Error */
    return status;
  }
  if (HAL_AES_SetDataSwapping(pSAES, HAL_AES_DATA_SWAPPING_NO) != HAL_OK)
  {
    return status;
  }
  if (HAL_AES_UnwrapKey(pSAES, p_key, aes_key_size, KWE_TIMEOUT_VALUE) != HAL_OK)
  {
    /* Processing Error */
    return status;
  }

  status = KWE_SUCCESS;

  return status;
}

#if defined(USE_HAL_AES_CCM_ALGO) && (USE_HAL_AES_CCM_ALGO == 1)
/**
  * @brief  A function that performs AES authenticated encryption operation
  *         using KWE hardware accelerator.
  * @param  alg : an AES AEAD algorithm.
  * @param  p_key_buffer : a pointer to buffer that contain the wrapped key.
  * @param  key_buffer_size : size of the wrapped  key buffer in bytes.

  * @param  p_nonce : a pointer to nonce or initialization vectors (IV).
  * @param  nonce_length : Size of the nonce or IV buffer in bytes.
  * @param  p_additional_data : a pointer to additional data that will be
  *                             authenticated but not encrypted.
  * @param  additional_data_length : Size of additional data in bytes.
  * @param  p_plaintext : pointer data that will be authenticated and encrypted.
  * @param  plaintext_length: Size of data in bytes.
  * @param  p_ciphertext : Output buffer for the authenticated tag and encrypted
  *                        data.
  * @param  ciphertext_size : Size of the Output buffer in bytes.
  * @param  p_ciphertext_length : The size of the actual output cipher in bytes.
  * @param  tag_length : The size of the authentication tag in bytes, maximum is 16 bytes.
  * @retval KWE_SUCCESS if success, an error code otherwise
  */
kwe_status_t KWE_AeadEncrypt(
  kwe_algorithm_t alg,
  const uint8_t *p_key_buffer, size_t key_buffer_size,
  const uint8_t *p_nonce, size_t nonce_length,
  const uint8_t *p_additional_data, size_t additional_data_length,
  const uint8_t *p_plaintext, size_t plaintext_length,
  uint8_t *p_ciphertext, size_t ciphertext_size, size_t *p_ciphertext_length,
  uint8_t tag_length)
{
  pSAES = mx_stfcf_kwe_saes_gethandle();
  kwe_status_t status = KWE_ERROR;
  __ALIGN_BEGIN uint8_t init_vect[16] __ALIGN_END = {0};
  uint32_t *p_iv  = (uint32_t *)init_vect;
  uint32_t i = 0;
  size_t len_left = 0;
  uint32_t msg_len_bytes = 0;
  unsigned char *b1_padded_addr = NULL;             /* Formatting of B1  */
  size_t b1_length = 0;                             /* B1 with padding   */
  uint8_t b1_padding = 0;                           /* B1 word alignment */
  __ALIGN_BEGIN uint8_t tag[16] __ALIGN_END = {0};  /* temporary tag     */

  if ((((uint64_t) additional_data_length >> 61U) != 0U) || (nonce_length > 16U))
  {
    goto exit;
  }

  if (KWE_AES_UnwrapKey(p_key_buffer, key_buffer_size) != KWE_SUCCESS)
  {
    goto exit;
  }

  /* Reconfigure the SAES for GCM */
  if ((alg == KWE_ALG_AES_GCM) && (additional_data_length != 0U))
  {
    /* Set Initialization vector (IV) in Little endian format */
    for (i = 0; i < (nonce_length / 4U); i++)
    {
      GET_UINT32_BE(p_iv[i], p_nonce, 4U * i);
    }

    /* counter value must be set to 2 when processing the first block of payload */
    p_iv[3] = 0x00000002;
    conf_gcm.p_init_vect = p_iv;
    conf_gcm.p_header = (uint32_t *) p_additional_data;
    conf_gcm.header_size_byte = additional_data_length;

    if (HAL_AES_GCM_GMAC_SetConfig(pSAES, &conf_gcm) != HAL_OK)
    {
      goto exit;
    }

    if (HAL_AES_SetDataSwapping(pSAES, HAL_AES_DATA_SWAPPING_BYTE) != HAL_OK)
    {
      goto exit;
    }

    if (HAL_AES_Encrypt(pSAES, p_plaintext, (uint16_t)plaintext_length, p_ciphertext,
                        KWE_TIMEOUT_VALUE) != HAL_OK)
    {
      goto exit;
    }

    /* Compute the authentication TAG in an aligned buffer: (p_ciphertext + plaintext_length) is not
       guaranteed to be 4-byte aligned since plaintext_length is an arbitrary byte length */
    if (HAL_AES_GCM_GenerateAuthTAG(pSAES, (uint32_t *) tag, KWE_TIMEOUT_VALUE) != HAL_OK)
    {
      goto exit;
    }

    (void) memcpy((p_ciphertext + plaintext_length), tag, tag_length);
  }

  else if ((alg == KWE_ALG_AES_CCM) && (additional_data_length != 0U))
  {
    /* Also implies msg_len_bytes is within bounds */
    if ((nonce_length < 7U) || (nonce_length > 13U))
    {
      goto exit;
    }

    (void) memcpy(init_vect + 1, p_nonce, nonce_length);

    msg_len_bytes = (uint8_t)(16U - 1U - nonce_length);
    init_vect[0] |= (uint8_t)(additional_data_length > 0U) << 6U;
    init_vect[0] |= ((tag_length - 2U) / 2U) << 3U;
    init_vect[0] |= (uint8_t)(msg_len_bytes - 1U);

    len_left = plaintext_length;
    for (i = 0; i < msg_len_bytes; i++)
    {
      init_vect[15U - i] = (uint8_t)((len_left) & 0xffU);
      len_left >>= 8U;
    }

    if (len_left > 0U)
    {
      goto exit;
    }

    /* first authentication block */
    for (i = 0U; i < 4U; i++)
    {
      GET_UINT32_BE(p_iv[i], init_vect, 4U * i);
    }

    conf_ccm.p_b0 = p_iv;
    /* Extra bytes to deal with data padding such that
     * the resulting string can be partitioned into words
     */
    b1_padding = (uint8_t)((additional_data_length + 2U) % 4U);
    b1_length = additional_data_length + 2U + b1_padding;

    b1_padded_addr = calloc(1, b1_length);

    if (b1_padded_addr == NULL)
    {
      goto exit;
    }

    /* Header length */
    b1_padded_addr[0] = (unsigned char)((additional_data_length >> 8U) & 0xFFU);
    b1_padded_addr[1] = (unsigned char)((additional_data_length) & 0xFFU);

    /* data concatenation */
    (void) memcpy(b1_padded_addr + 2U, p_additional_data, additional_data_length);

    /* blocks (B) associated to the Associated Data (A) */
    conf_ccm.p_header     = (uint32_t *)b1_padded_addr;
    conf_ccm.header_size_byte = b1_length;

    if (HAL_AES_CCM_SetConfig(pSAES, &conf_ccm) != HAL_OK)
    {
      goto exit;
    }

    if (HAL_AES_SetDataSwapping(pSAES, HAL_AES_DATA_SWAPPING_BYTE) != HAL_OK)
    {
      goto exit;
    }

    if (HAL_AES_Encrypt(pSAES, p_plaintext, (uint16_t)plaintext_length, p_ciphertext,
                        KWE_TIMEOUT_VALUE) != HAL_OK)
    {
      goto exit;
    }

    /* Compute the authentication TAG */
    if (HAL_AES_CCM_GenerateAuthTAG(pSAES, (uint32_t *) tag, KWE_TIMEOUT_VALUE) != HAL_OK)
    {
      goto exit;
    }

    (void) memcpy((p_ciphertext + plaintext_length), tag, tag_length);
  }
  else if (additional_data_length == 0U)
  {
    pSAES->p_header = NULL;
    pSAES->header_size_byte = 0U;
  }
  else
  {
    return KWE_ERROR_NOT_SUPPORTED;
  }

  *p_ciphertext_length = ciphertext_size;

  status = KWE_SUCCESS;

exit:
  if (alg == KWE_ALG_AES_CCM)
  {
    free(b1_padded_addr);
  }
  return status;

}

/**
  * @brief  A function that performs AES authenticated decryption operation
  *         using KWE hardware accelerator.
  * @param  alg : an AES AEAD algorithm.
  * @param  p_key_buffer : a pointer to buffer that contain the wrapped key.
  * @param  key_buffer_size : size of the wrapped  key buffer in bytes.

  * @param  p_nonce : a pointer to nonce or initialization vectors (IV).
  * @param  nonce_length : Size of the nonce or IV buffer in bytes.
  * @param  p_additional_data : Additional data that has been authenticated
  *                             but not encrypted
  * @param  additional_data_length : Size of additional data in bytes.
  * @param  p_ciphertext : a pointer to encrypted data and authenticated tag.
  * @param  ciphertext_length : Size of encrypted data and authenticated tag
  *                             buffer in bytes.
  * @param  p_plaintext : a pointer to output buffer for the decrypted data.
  * @param  plaintext_size : Size of the output buffer in bytes.
  * @param  p_plaintext_length : the size of the actual decrypted data in bytes.
  * @param  tag_length : The size of the authentication tag in bytes.
  * @retval KWE_SUCCESS if success, an error code otherwise
  */
kwe_status_t KWE_AeadDecrypt(
  kwe_algorithm_t alg,
  const uint8_t *p_key_buffer, size_t key_buffer_size,
  const uint8_t *p_nonce, size_t nonce_length,
  const uint8_t *p_additional_data, size_t additional_data_length,
  const uint8_t *p_ciphertext, size_t ciphertext_length,
  uint8_t *p_plaintext, size_t plaintext_size, size_t *p_plaintext_length,
  uint8_t tag_length)
{
  pSAES = mx_stfcf_kwe_saes_gethandle();
  kwe_status_t status = KWE_ERROR;
  __ALIGN_BEGIN uint8_t init_vect[16] __ALIGN_END = {0};
  uint32_t *p_iv  = (uint32_t *)init_vect;
  __ALIGN_BEGIN uint8_t work_buf[16] __ALIGN_END;
  __ALIGN_BEGIN uint8_t check_tag[16] __ALIGN_END = {0};
  size_t cipher_length = 0U;
  size_t cipher_block_size = 0U;
  size_t last_bytes = 0;
  uint32_t i = 0;
  size_t len_left = 0;
  uint32_t msg_len_bytes = 0;
  unsigned char *b1_padded_addr = NULL;            /* Formatting of B1   */
  size_t b1_length = 0;                            /* B1 with padding    */
  uint8_t b1_padding = 0;                          /* B1 word alignment  */

  if ((((uint64_t) additional_data_length >> 61U) != 0U) || (nonce_length > 16U))
  {
    goto exit;
  }

  if (KWE_AES_UnwrapKey(p_key_buffer, key_buffer_size) != KWE_SUCCESS)
  {
    goto exit;
  }

  if ((alg == KWE_ALG_AES_GCM) && (additional_data_length != 0U))
  {
    /* Set Initialization vector (IV) in Little endian format */
    for (i = 0; i < (nonce_length / 4U); i++)
    {
      GET_UINT32_BE(p_iv[i], p_nonce, 4U * i);
    }

    /* Counter value must be set to 2 when processing the first block of payload */
    p_iv[3] = 0x00000002;
    conf_gcm.p_init_vect = p_iv;
    /* Additional authentication data limited to 2^64 bits */
    conf_gcm.p_header = (uint32_t *)p_additional_data;  /* p_aad */
    conf_gcm.header_size_byte = additional_data_length;

    if (HAL_AES_GCM_GMAC_SetConfig(pSAES, &conf_gcm) != HAL_OK)
    {
      goto exit;
    }
  }
  else if ((alg == KWE_ALG_AES_CCM) && (additional_data_length != 0U))
  {
    /* Also implies msg_len_bytes is within bounds */
    if ((nonce_length < 7U) || (nonce_length > 13U))
    {
      goto exit;
    }

    (void) memcpy(init_vect + 1U, p_nonce, nonce_length);

    msg_len_bytes = (uint8_t)(16U - 1U - nonce_length);
    init_vect[0] |= (uint8_t)(additional_data_length > 0U) << 6U;
    init_vect[0] |= ((tag_length - 2U) / 2U) << 3U;
    init_vect[0] |= (uint8_t)(msg_len_bytes - 1U);

    len_left = (ciphertext_length - tag_length);
    for (i = 0U; i < msg_len_bytes; i++)
    {
      init_vect[15U - i] = (uint8_t)((len_left) & 0xFFU);
      len_left >>= 8U;
    }

    if (len_left > 0U)
    {
      goto exit;
    }
    /* first authentication block */
    for (i = 0U; i < 4U; i++)
    {
      GET_UINT32_BE(p_iv[i], init_vect, 4U * i);
    }
    conf_ccm.p_b0 = p_iv;
    /* Extra bytes to deal with data padding such that
     * the resulting string can be partitioned into words
     */
    b1_padding = (uint8_t)((additional_data_length + 2U) % 4U);
    b1_length = additional_data_length + 2U + b1_padding;

    b1_padded_addr = calloc(1, b1_length);

    if (b1_padded_addr == NULL)
    {
      goto exit;
    }

    /* Header length */
    b1_padded_addr[0] = (unsigned char)((additional_data_length >> 8U) & 0xFFU);
    b1_padded_addr[1] = (unsigned char)((additional_data_length) & 0xFFU);

    /* data concatenation */
    (void) memcpy(b1_padded_addr + 2U, p_additional_data, additional_data_length);

    /* blocks (B) associated to the Associated Data (A) */
    conf_ccm.p_header     = (uint32_t *)b1_padded_addr;
    conf_ccm.header_size_byte = b1_length;

    if (HAL_AES_CCM_SetConfig(pSAES, &conf_ccm) != HAL_OK)
    {
      goto exit;
    }
  }
  else if (additional_data_length == 0U)
  {
    conf_ccm.p_header = NULL;
    conf_ccm.header_size_byte = 0U;
  }
  else
  {
    return KWE_ERROR_NOT_SUPPORTED;
  }

  if (HAL_AES_SetDataSwapping(pSAES, HAL_AES_DATA_SWAPPING_BYTE) != HAL_OK)
  {
    goto exit;
  }

  cipher_length = ciphertext_length - tag_length;
  cipher_block_size = (cipher_length / 16U) * 16U;

  if (HAL_AES_Decrypt(pSAES, p_ciphertext, (uint16_t)cipher_block_size, p_plaintext,
                      KWE_TIMEOUT_VALUE) != HAL_OK)
  {
    goto exit;
  }

  /* decrypt last bytes */
  last_bytes = cipher_length % 16U;

  if (last_bytes != 0U)
  {
    (void) memset(work_buf, 0, sizeof(work_buf));
    (void) memcpy(work_buf, p_ciphertext + cipher_block_size, last_bytes);

    if (HAL_AES_Decrypt(pSAES, (uint32_t *)work_buf, (uint16_t)last_bytes,
                        (uint32_t *)(p_plaintext + cipher_block_size),
                        KWE_TIMEOUT_VALUE) != HAL_OK)
    {
      goto exit;
    }
  }

  /* Tag generation */
  if (alg == KWE_ALG_AES_GCM)
  {
    /* Compute the authentication TAG */
    if (HAL_AES_GCM_GenerateAuthTAG(pSAES, (uint32_t *)(check_tag), KWE_TIMEOUT_VALUE) != HAL_OK)
    {
      goto exit;
    }
  }
  else if (alg == KWE_ALG_AES_CCM)
  {
    /* Compute the authentication TAG */
    if (HAL_AES_CCM_GenerateAuthTAG(pSAES, (uint32_t *)(check_tag), KWE_TIMEOUT_VALUE) != HAL_OK)
    {
      goto exit;
    }
  }
  else
  {
    goto exit;
  }

  if (memcmp(check_tag, p_ciphertext + plaintext_size, tag_length) != 0)
  {
    goto exit;
  }

  *p_plaintext_length = plaintext_size;

  status = KWE_SUCCESS;

exit:
  if (alg == KWE_ALG_AES_CCM)
  {
    free(b1_padded_addr);
  }
  return status;
}

#endif /* USE_HAL_AES_GCM_GMAC_ALGO or USE_HAL_AES_CCM_ALGO */

/**
  * @brief  A function that performs AES encryption cipher using KWE
  *         hardware accelerator.
  * @param  p_key_buffer : a pointer to buffer that contain the wrapped key.
  * @param  key_buffer_size : size of the wrapped  key buffer in bytes.
  * @param  alg : a cipher algorithm.
  * @param  p_iv : a pointer to initialization vectors (IV).
  * @param  iv_length : Size of the IV buffer in bytes.
  * @param  p_plaintext : pointer data that will be encrypted.
  * @param  plaintext_length: Size of data in bytes.
  * @param  p_ciphertext : Output buffer for the encrypted data.
  * @param  ciphertext_size : Size of the Output buffer in bytes.
  * @param  p_ciphertext_length : The size of the actual output cipher in bytes.
  * @retval KWE_SUCCESS if success, an error code otherwise
  */
kwe_status_t KWE_Encrypt(
  kwe_algorithm_t alg,
  const uint8_t *p_key_buffer, size_t key_buffer_size,
  const uint8_t *p_iv, size_t iv_length,
  const uint8_t *p_plaintext, size_t plaintext_length,
  uint8_t *p_ciphertext, size_t ciphertext_size, size_t *p_ciphertext_length)
{
  pSAES = mx_stfcf_kwe_saes_gethandle();
  kwe_status_t status = KWE_ERROR;
  uint32_t init_vect[4] = {0};
  uint32_t i = 0;

  if (KWE_AES_UnwrapKey(p_key_buffer, key_buffer_size) != KWE_SUCCESS)
  {
    return status;
  }
  if (alg == KWE_ALG_AES_CBC)
  {
    /* Set Initialization vector (IV) in Little endian format */
    for (i = 0; i < (iv_length / 4U); i++)
    {
      GET_UINT32_BE(init_vect[i], p_iv, 4U * i);
    }

    if (HAL_AES_CBC_SetConfig(pSAES, init_vect) != HAL_OK)
    {
      return status;
    }
  }
  else
  {
    if (HAL_AES_ECB_SetConfig(pSAES) != HAL_OK)
    {
      return status;
    }
  }
  if (HAL_AES_SetDataSwapping(pSAES, HAL_AES_DATA_SWAPPING_BYTE) != HAL_OK)
  {
    return status;
  }
  if (HAL_AES_Encrypt(pSAES, (uint32_t *)p_plaintext, (uint16_t)plaintext_length, (uint32_t *)p_ciphertext,
                      KWE_TIMEOUT_VALUE) != HAL_OK)
  {
    return status;
  }
  *p_ciphertext_length = ciphertext_size;

  status = KWE_SUCCESS;

  return status;
}

/**
  * @brief  A function that performs AES decryption operation using KWE
  *         hardware accelerator.
  * @param  p_key_buffer : a pointer to buffer that contain the wrapped key.
  * @param  key_buffer_size : size of the wrapped  key buffer in bytes.
  * @param  alg : a cipher algorithm.

  * @param  p_ciphertext : a pointer to encrypted data and IV.
  * @param  ciphertext_length : Size of encrypted data and IV.
  * @param  p_plaintext : a pointer to output buffer for the decrypted data.
  * @param  plaintext_size : Size of the output buffer in bytes.
  * @param  p_plaintext_length : the size of the actual decrypted data in bytes.
  * @retval KWE_SUCCESS if success, an error code otherwise
  */
kwe_status_t KWE_Decrypt(
  kwe_algorithm_t alg,
  const uint8_t *p_key_buffer, size_t key_buffer_size,
  const uint8_t *p_ciphertext, size_t ciphertext_length,
  uint8_t *p_plaintext, size_t plaintext_size, size_t *p_plaintext_length)
{
  (void) plaintext_size;
  pSAES = mx_stfcf_kwe_saes_gethandle();
  kwe_status_t status = KWE_ERROR;
  uint32_t init_vect[4] = {0};
  uint32_t i = 0;
  *p_plaintext_length = 0U;

  if (KWE_AES_UnwrapKey(p_key_buffer, key_buffer_size) != KWE_SUCCESS)
  {
    return status;
  }

#if defined(AES_CR_KEYPROT)
  /* Prevent SAES key from being accessed by another security context */
  if (HAL_AES_EnableKeyProtection(pSAES) != HAL_OK)
  {
    return status;
  }
#endif /* AES_CR_KEYPROT */

  if (alg == KWE_ALG_AES_CBC)
  {
    /* Set Initialization vector (IV) in Little endian format */
    for (i = 0; i < (KWE_IV_MAX_SIZE / 4U); i++)
    {
      GET_UINT32_BE(init_vect[i], p_ciphertext, 4U * i);
    }

    if (HAL_AES_CBC_SetConfig(pSAES, init_vect) != HAL_OK)
    {
      return status;
    }
    if (HAL_AES_SetDataSwapping(pSAES, HAL_AES_DATA_SWAPPING_BYTE) != HAL_OK)
    {
      return status;
    }
    if (HAL_AES_Decrypt(pSAES, (uint32_t *)(p_ciphertext + KWE_IV_MAX_SIZE),
                        (uint16_t)ciphertext_length - (uint16_t)KWE_IV_MAX_SIZE,
                        (uint32_t *)p_plaintext, KWE_TIMEOUT_VALUE) != HAL_OK)
    {
      return status;
    }

    *p_plaintext_length = ciphertext_length - KWE_IV_MAX_SIZE;
  }
  else
  {
    if (HAL_AES_ECB_SetConfig(pSAES) != HAL_OK)
    {
      return status;
    }

    if (HAL_AES_SetDataSwapping(pSAES, HAL_AES_DATA_SWAPPING_BYTE) != HAL_OK)
    {
      return status;
    }

    if (HAL_AES_Decrypt(pSAES, (uint32_t *)p_ciphertext, (uint16_t)ciphertext_length, (uint32_t *)p_plaintext,
                        KWE_TIMEOUT_VALUE) != HAL_OK)
    {
      return status;
    }

    *p_plaintext_length = ciphertext_length;
  }

  status = KWE_SUCCESS;

  return status;
}
#endif /* KWE_SYMMETRIC_KEY_WRAP_ENABLED */
/**
  * @}
  */

/**
  * @}
  */

#endif /* KWE_DRIVER_ENABLED */

/**
  * @}
  */

/**
  * @}
  */
