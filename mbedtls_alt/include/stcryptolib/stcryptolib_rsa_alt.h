/**
  ******************************************************************************
  * @file    rsa_alt.h
  * @brief   Header for rsa_alt module
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
  * @brief This file provides an API for the RSA public-key cryptosystem based
  *        on STM32 crypto library.
  *
  * The RSA public-key cryptosystem is defined in <em>Public-Key
  * Cryptography Standards (PKCS) #1 v1.5: RSA Encryption</em>
  * and <em>Public-Key Cryptography Standards (PKCS) #1 v2.1:
  * RSA Cryptography Specifications</em>.
  *
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef MBEDTLS_STCRYPTOLIB_RSA_ALT_H
#define MBEDTLS_STCRYPTOLIB_RSA_ALT_H

#if defined(MBEDTLS_RSA_ALT)

#if defined(MBEDTLS_STCRYPTOLIB_RSA_ALT)
#include "cmox_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ST_MD_MAX_SIZE 64    /* longest known is SHA512 */
#define ST_MOD_MAX_SIZE 3072 /* longest known is TFM is 3072 */
#define PUBLIC_EXP_LEN 3     /* Default value is always 65536 */

/* Regular implementation */

/**
  * @brief   The RSA context structure.
  *
  * @note    Direct manipulation of the members of this structure
  *          is deprecated. All manipulation must instead be done through
  *          the public interface functions.
  */

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_RSA_ALT_TYPES STCRYPTOLIB RSA Types
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief RSA context structure definitions for STCRYPTOLIB.
  * @{
  */

typedef struct mbedtls_rsa_context
{
  cmox_rsa_handle_t rsa_ctx;   /*!<  ptr on rsa generic ctx */

  int ver;                    /*!<  Always 0.*/
  size_t len;                 /*!<  The size of \p N in Bytes. */

  mbedtls_mpi N;              /*!<  The public modulus. */
  mbedtls_mpi E;              /*!<  The public exponent. */

  mbedtls_mpi D;              /*!<  The private exponent. */
  mbedtls_mpi P;              /*!<  The first prime factor. */
  mbedtls_mpi Q;              /*!<  The second prime factor. */

  mbedtls_mpi DP;             /*!<  <code>D % (P - 1)</code>. */
  mbedtls_mpi DQ;             /*!<  <code>D % (Q - 1)</code>. */
  mbedtls_mpi QP;             /*!<  <code>1 / (Q % P)</code>. */

  mbedtls_mpi RN;             /*!<  cached <code>R^2 mod N</code>. */

  mbedtls_mpi RP;             /*!<  cached <code>R^2 mod P</code>. */
  mbedtls_mpi RQ;             /*!<  cached <code>R^2 mod Q</code>. */

  mbedtls_mpi Vi;             /*!<  The cached blinding value. */
  mbedtls_mpi Vf;             /*!<  The cached un-blinding value. */

  int padding;                /*!< Selects padding mode:
                                   #MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
                                   #MBEDTLS_RSA_PKCS_V21 for OAEP or PSS. */
  int hash_id;                /*!< Hash identifier of mbedtls_md_type_t type,
                                   as specified in md.h for use in the MGF
                                   mask generating function used in the
                                   EME-OAEP and EMSA-PSS encodings. */
#if defined(MBEDTLS_THREADING_C)
  mbedtls_threading_mutex_t mutex;    /*!<  Thread-safety mutex. */
#endif  /* MBEDTLS_THREADING_C */
}
mbedtls_rsa_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_STCRYPTOLIB_RSA_ALT */

#endif /* MBEDTLS_RSA_ALT */
#endif /* MBEDTLS_STCRYPTOLIB_RSA_ALT_H */

/**
  * @}
  */
