/**
  ******************************************************************************
  * @file    kwe_core.h
  * @brief   Header for kwe_core.c module
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
#ifndef KWE_CORE_H
#define KWE_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "mx_kwe_config.h"
#include "kwe_types.h"

/** @addtogroup KWE_MODULES
  * @{
  */

/** @addtogroup KWE_CORE
  * @{
  */

/* Exported types ------------------------------------------------------------*/
/* Exported constants --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported variables --------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
/** @addtogroup KWE_CORE_Exported_Functions
  * @{
  */

/** @addtogroup KWE_CORE_Exported_Functions_Group1
  * @{
  */

kwe_status_t KWE_EccGenerateWrappedKey(
  kwe_ecp_t *p_ecp,
  kwe_algorithm_t ecc_alg,
  uint8_t *p_key_buffer,
  size_t key_buffer_size,
  size_t *p_key_buffer_length);

kwe_status_t KWE_EccWrapKey(
  kwe_ecp_t *p_ecp,
  kwe_algorithm_t ecc_alg,
  const uint8_t *p_data,
  uint8_t *p_key_buffer,
  size_t key_buffer_size,
  size_t *p_key_buffer_length);

kwe_status_t KWE_RsaWrapKey(
  kwe_rsa_t *p_rsa,
  uint8_t *p_key_buffer,
  size_t *p_key_buffer_length);

/**
  * @}
  */

/** @addtogroup KWE_CORE_Exported_Functions_Group2
  * @{
  */

kwe_status_t KWE_EcdsaPublicKeyExport(
  kwe_ecp_t *p_ecp,
  const uint8_t *p_key_buffer,
  uint8_t *p_public_key,
  size_t public_key_size,
  size_t *p_public_key_length);

kwe_status_t KWE_EcdhKeyAgreement(
  kwe_ecp_t *p_ecp,
  const uint8_t *p_key_buffer,
  const uint8_t *p_peer_key,
  size_t peer_key_length,
  uint8_t *p_shared_secret,
  size_t shared_secret_size,
  size_t *p_shared_secret_length);

/**
  * @}
  */

/** @addtogroup KWE_CORE_Exported_Functions_Group3
  * @{
  */

kwe_status_t KWE_EcdsaSignHash(
  kwe_ecp_t *p_ecp,
  const uint8_t *p_key_buffer,
  const uint8_t *p_hash,
  uint8_t hash_length,
  uint8_t *p_signature,
  size_t signature_size,
  size_t *p_signature_length);


kwe_status_t KWE_RsaModularExp(
  kwe_rsa_t *p_rsa,
  const uint8_t *p_key_buffer,
  const uint8_t *p_input,
  uint8_t *p_output);
/**
  * @}
  */

/** @addtogroup KWE_CORE_Exported_Functions_Group4
  * @{
  */
#if defined(KWE_SYMMETRIC_KEY_WRAP_ENABLED)
kwe_status_t KWE_WrapKey(
  const uint8_t *p_data,
  size_t data_length,
  uint8_t *p_key_buffer,
  size_t key_buffer_size,
  size_t *p_key_buffer_length);

kwe_status_t KWE_AeadEncrypt(
  kwe_algorithm_t alg,
  const uint8_t *p_key_buffer, size_t key_buffer_size,
  const uint8_t *p_nonce, size_t nonce_length,
  const uint8_t *p_additional_data, size_t additional_data_length,
  const uint8_t *p_plaintext, size_t plaintext_length,
  uint8_t *p_ciphertext, size_t ciphertext_size, size_t *p_ciphertext_length,
  uint8_t tag_length);

kwe_status_t KWE_AeadDecrypt(
  kwe_algorithm_t alg,
  const uint8_t *p_key_buffer, size_t key_buffer_size,
  const uint8_t *p_nonce, size_t nonce_length,
  const uint8_t *p_additional_data, size_t additional_data_length,
  const uint8_t *p_ciphertext, size_t ciphertext_length,
  uint8_t *p_plaintext, size_t plaintext_size, size_t *p_plaintext_length,
  uint8_t tag_length);

kwe_status_t KWE_Encrypt(
  kwe_algorithm_t alg,
  const uint8_t *p_key_buffer, size_t key_buffer_size,
  const uint8_t *p_nonce, size_t nonce_length,
  const uint8_t *p_plaintext, size_t plaintext_length,
  uint8_t *p_ciphertext, size_t ciphertext_size, size_t *p_ciphertext_length);

kwe_status_t KWE_Decrypt(
  kwe_algorithm_t alg,
  const uint8_t *p_key_buffer, size_t key_buffer_size,
  const uint8_t *p_input, size_t input_length,
  uint8_t *p_output, size_t output_size, size_t *p_output_length);
#endif  /* KWE_SYMMETRIC_KEY_WRAP_ENABLED */
/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

#ifdef __cplusplus
}
#endif

#endif /*KWE_CORE_H */
