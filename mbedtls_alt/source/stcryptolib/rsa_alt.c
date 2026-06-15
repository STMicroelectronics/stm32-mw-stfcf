/**
  ******************************************************************************
  * @file    rsa_alt.c
  * @brief   Implementation of mbedtls_alt RSA module
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
  * The RSA public-key cryptosystem
  *
  * This file implements ST RSA based on STM32 crypto library.
  *
  */

/*
 *  The following sources were referenced in the design of this implementation
 *  of the RSA algorithm:
 *
 *  [1] A method for obtaining digital signatures and public-key cryptosystems
 *      R Rivest, A Shamir, and L Adleman
 *      http://people.csail.mit.edu/rivest/pubs.html#RSA78
 *
 *  [2] Handbook of Applied Cryptography - 1997, Chapter 8
 *      Menezes, van Oorschot and Vanstone
 *
 *  [3] Malware Guard Extension: Using SGX to Conceal Cache Attacks
 *      Michael Schwarz, Samuel Weiser, Daniel Gruss, Clementine Maurice and
 *      Stefan Mangard
 *      https://arxiv.org/abs/1702.08719v2
 *
 */

/* Includes ------------------------------------------------------------------*/
#include "common.h"

#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_RSA_ALT)

#include "mbedtls/rsa.h"
#include "bignum_core.h"
#include "bignum_internal.h"
#include "rsa_alt_helpers.h"
#include "rsa_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"
#include "md_psa.h"

#include <string.h>

#define MBEDTLS_MPI_CHK_RSA_ALT(f)       \
  do                           \
  {                            \
    ret = (f);                 \
    if (ret != 0)              \
    {                          \
      goto cleanup;            \
    }                          \
  } while (0)

#if defined(MBEDTLS_PKCS1_V15) && !defined(__OpenBSD__) && !defined(__NetBSD__)
#include <stdlib.h>
#endif /* MBEDTLS_PKCS1_V15 and not __OpenBSD__ */

#include "mbedtls/platform.h"

#if defined(MBEDTLS_STCRYPTOLIB_RSA_ALT)

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define ST_BUFFER_SIZE_PKCS1_V15  3500;
#define ST_BUFFER_SIZE_PKCS1_V21  7000;

/* Private macro -------------------------------------------------------------*/

/** @defgroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB_RSA_ALT_FUNCTIONS STCRYPTOLIB RSA Functions
  * @ingroup MBEDTLS_IMPLEMENTATION_STCRYPTOLIB
  * @brief Public API functions for STCRYPTOLIB RSA alternate implementation.
  * @{
  */

/** @cond DOXYGEN_SHOULD_SKIP_THIS */
/**
  * @brief Convert return value from STCryptoLib to MBED for rsa
  */
static int rsa_mbed_return_value(cmox_rsa_retval_t retval)
{
  int ret = 0; /* Return value */

  switch (retval)
  {
    case CMOX_RSA_SUCCESS:
      ret = 0;
      break;

    case CMOX_RSA_ERR_INTERNAL:
      ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      break;

    case CMOX_RSA_ERR_BAD_PARAMETER:
      ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
      break;

    case CMOX_RSA_ERR_MODULUS_TOO_SHORT:
      ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
      break;

    case CMOX_RSA_ERR_INVALID_SIGNATURE:
      ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
      break;

    case CMOX_RSA_ERR_WRONG_DECRYPTION:
      ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
      break;

    case CMOX_RSA_ERR_WRONG_RANDOM:
      ret = MBEDTLS_ERR_RSA_RNG_FAILED;
      break;

    case CMOX_RSA_ERR_MEMORY_FAIL:
      ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
      break;

    case CMOX_RSA_ERR_MATH_ALGO_MISMATCH:
      ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
      break;

    case CMOX_RSA_ERR_MEXP_ALGO_MISMATCH:
      ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
      break;

    case CMOX_RSA_AUTH_SUCCESS:
      ret = 0;
      break;

    case CMOX_RSA_AUTH_FAIL:
      ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
      break;

    default :
      ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;
      break;
  }
  return ret;
}

#if defined(MBEDTLS_PKCS1_V15)
/**
  * @brief Convert a mbedtls_md_type_t to a cmox_rsa_pkcs1v15_hash_t for hash identification in RSA v1.5.
  *
  * This function returns the corresponding hash ID on success, or 0 otherwise.
  *
  * @return The corresponding cmox_rsa_pkcs1v15_hash_t hash ID if successful, 0 otherwise.
  */
static cmox_rsa_pkcs1v15_hash_t rsa_alt_hashId_1v15(mbedtls_md_type_t md_alg,
                                                    unsigned int hashlen)
{
  cmox_rsa_pkcs1v15_hash_t retval = 0; /* Return value */

  /* Select correct hash id */
  switch (md_alg)
  {
    case MBEDTLS_MD_SHA1:
      retval = CMOX_RSA_PKCS1V15_HASH_SHA1;
      break;

    case MBEDTLS_MD_SHA224:
      retval = CMOX_RSA_PKCS1V15_HASH_SHA224;
      break;

    case MBEDTLS_MD_SHA256:
      retval = CMOX_RSA_PKCS1V15_HASH_SHA256;
      break;

    case MBEDTLS_MD_SHA384:
      retval = CMOX_RSA_PKCS1V15_HASH_SHA384;
      break;

    case MBEDTLS_MD_SHA512:
      retval = CMOX_RSA_PKCS1V15_HASH_SHA512;
      break;

    default :
      retval = 0;
      break;
  }

  /* If Sha can be identified with mbedtls_md_type_t, use hash length */
  if (retval == 0)
  {
    if (hashlen == 20U)
    {
      retval = CMOX_RSA_PKCS1V15_HASH_SHA1;
    }
    else if (hashlen == 28U)
    {
      retval = CMOX_RSA_PKCS1V15_HASH_SHA224;
    }
    else if (hashlen == 32U)
    {
      retval = CMOX_RSA_PKCS1V15_HASH_SHA256;
    }
    else if (hashlen == 48U)
    {
      retval = CMOX_RSA_PKCS1V15_HASH_SHA384;
    }
    else if (hashlen == 64U)
    {
      retval = CMOX_RSA_PKCS1V15_HASH_SHA512;
    }
    else
    {
      retval = 0;
    }
  }
  return retval;
}
#endif /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
/**
  * @brief Convert a mbedtls_md_type_t to a cmox_rsa_pkcs1v22_hash_t for hash identification in RSA v2.1.
  *
  * This function returns the corresponding hash ID on success, or 0 otherwise.
  *
  * @return The corresponding cmox_rsa_pkcs1v22_hash_t hash ID if successful, 0 otherwise.
  */
static cmox_rsa_pkcs1v22_hash_t rsa_alt_hashId_1v22(mbedtls_md_type_t md_alg,
                                                    unsigned int hashlen)
{
  cmox_rsa_pkcs1v22_hash_t retval = 0; /* Return value */

  /* Select correct hash id */
  switch (md_alg)
  {
    case MBEDTLS_MD_SHA1:
      retval = CMOX_RSA_PKCS1V22_HASH_SHA1;
      break;

    case MBEDTLS_MD_SHA224:
      retval = CMOX_RSA_PKCS1V22_HASH_SHA224;
      break;

    case MBEDTLS_MD_SHA256:
      retval = CMOX_RSA_PKCS1V22_HASH_SHA256;
      break;

    case MBEDTLS_MD_SHA384:
      retval = CMOX_RSA_PKCS1V22_HASH_SHA384;
      break;

    case MBEDTLS_MD_SHA512:
      retval = CMOX_RSA_PKCS1V22_HASH_SHA512;
      break;

    default :
      retval = 0;
      break;
  }

  /* If Sha can be identified with mbedtls_md_type_t, use hash length */
  if (retval == 0)
  {
    if (hashlen == 20U)
    {
      retval = CMOX_RSA_PKCS1V22_HASH_SHA1;
    }
    else if (hashlen == 28U)
    {
      retval = CMOX_RSA_PKCS1V22_HASH_SHA224;
    }
    else if (hashlen == 32U)
    {
      retval = CMOX_RSA_PKCS1V22_HASH_SHA256;
    }
    else if (hashlen == 48U)
    {
      retval = CMOX_RSA_PKCS1V22_HASH_SHA384;
    }
    else if (hashlen == 64U)
    {
      retval = CMOX_RSA_PKCS1V22_HASH_SHA512;
    }
    else
    {
      retval = 0;
    }
  }
  return retval;
}
/** @endcond */
#endif /* MBEDTLS_PKCS1_V21 */

int mbedtls_rsa_import(mbedtls_rsa_context *ctx,
                       const mbedtls_mpi *N,
                       const mbedtls_mpi *P, const mbedtls_mpi *Q,
                       const mbedtls_mpi *D, const mbedtls_mpi *E)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

  if (N != NULL)
  {
    ret = mbedtls_mpi_copy(&ctx->N, N);
    if (ret != 0)
    {
      return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }
  }
  if (P != NULL)
  {
    ret = mbedtls_mpi_copy(&ctx->P, P);
    if (ret != 0)
    {
      return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }
  }
  if (Q != NULL)
  {
    ret = mbedtls_mpi_copy(&ctx->Q, Q);
    if (ret != 0)
    {
      return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }
  }
  if (D != NULL)
  {
    ret = mbedtls_mpi_copy(&ctx->D, D);
    if (ret != 0)
    {
      return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }
  }
  if (E != NULL)
  {
    ret = mbedtls_mpi_copy(&ctx->E, E);
    if (ret != 0)
    {
      return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }
  }

  if (N != NULL)
  {
    ctx->len = mbedtls_mpi_size(&ctx->N);
  }

  return 0;
}

int mbedtls_rsa_import_raw(mbedtls_rsa_context *ctx,
                           unsigned char const *N, size_t N_len,
                           unsigned char const *P, size_t P_len,
                           unsigned char const *Q, size_t Q_len,
                           unsigned char const *D, size_t D_len,
                           unsigned char const *E, size_t E_len)
{
  int ret = 0;

  if (N != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_read_binary(&ctx->N, N, N_len));
    ctx->len = mbedtls_mpi_size(&ctx->N);
  }

  if (P != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_read_binary(&ctx->P, P, P_len));
  }

  if (Q != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_read_binary(&ctx->Q, Q, Q_len));
  }

  if (D != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_read_binary(&ctx->D, D, D_len));
  }

  if (E != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_read_binary(&ctx->E, E, E_len));
  }

cleanup:

  if (ret != 0)
  {
    return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
  }

  return 0;
}

/** @cond DOXYGEN_SHOULD_SKIP_THIS */
/**
  * @brief Checks whether the context fields are set so that the RSA primitives can execute without error.
  *
  * @details
  * This function does *not* make guarantees for consistency of the parameters.
  */
static int rsa_check_context(mbedtls_rsa_context const *ctx, int is_priv,
                             int blinding_needed)
{
  int cmp_int = mbedtls_mpi_cmp_int(&ctx->N, 0);
  int get_bit = mbedtls_mpi_get_bit(&ctx->N, 0);
#if defined(MBEDTLS_RSA_NO_CRT)
  int cmp_d = mbedtls_mpi_cmp_int(&ctx->D, 0);
  int cmp_p = mbedtls_mpi_cmp_int(&ctx->P, 0);
  int cmp_q = mbedtls_mpi_cmp_int(&ctx->Q, 0);
#else
  /* blinding_needed is only used for NO_CRT to decide whether
   * P,Q need to be present or not. */
  ((void) blinding_needed);
#endif /* MBEDTLS_RSA_NO_CRT */

  if ((ctx->len != mbedtls_mpi_size(&ctx->N))
      || (ctx->len > (size_t) MBEDTLS_MPI_MAX_SIZE))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /*
   * 1. Modular exponentiation needs positive, odd moduli.
   */

  /* Modular exponentiation wrt. N is always used for
   * RSA public key operations. */
  if ((cmp_int <= 0) || (get_bit == 0))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

#if !defined(MBEDTLS_RSA_NO_CRT)
  /* Modular exponentiation for P and Q is only
   * used for private key operations and if CRT
   * is used. */
  if (is_priv
      && (mbedtls_mpi_cmp_int(&ctx->P, 0) <= 0
          || mbedtls_mpi_get_bit(&ctx->P, 0) == 0
          || mbedtls_mpi_cmp_int(&ctx->Q, 0) <= 0
          || mbedtls_mpi_get_bit(&ctx->Q, 0) == 0))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }
#endif /* !MBEDTLS_RSA_NO_CRT */

  /*
   * 2. Exponents must be positive
   */

  /* Always need E for public key operations */
  if (mbedtls_mpi_cmp_int(&ctx->E, 0) <= 0)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

#if defined(MBEDTLS_RSA_NO_CRT)
  /* For private key operations, use D or DP & DQ
   * as (unblinded) exponents. */
  if ((is_priv != 0) && (cmp_d <= 0))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }
#else
  if (is_priv
      && (mbedtls_mpi_cmp_int(&ctx->DP, 0) <= 0
          || mbedtls_mpi_cmp_int(&ctx->DQ, 0) <= 0))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }
#endif /* MBEDTLS_RSA_NO_CRT */

  /* Blinding shouldn't make exponents negative either,
   * so check that P, Q >= 1 if that hasn't yet been
   * done as part of 1. */
#if defined(MBEDTLS_RSA_NO_CRT)
  if ((is_priv != 0) && (blinding_needed != 0)
      && ((cmp_p <= 0) || (cmp_q <= 0)))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }
#endif /* MBEDTLS_RSA_NO_CRT */

  /* It wouldn't lead to an error if it wasn't satisfied,
   * but check for QP >= 1 nonetheless. */
#if !defined(MBEDTLS_RSA_NO_CRT)
  if (is_priv
      && mbedtls_mpi_cmp_int(&ctx->QP, 0) <= 0)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }
#endif /* !MBEDTLS_RSA_NO_CRT */

  return 0;
}
/** @endcond */

int mbedtls_rsa_complete(mbedtls_rsa_context *ctx)
{
  int ret = 0;
  int have_N = 0;
  int have_P = 0;
  int have_Q = 0;
  int have_D = 0;
  int have_E = 0;
#if !defined(MBEDTLS_RSA_NO_CRT)
  int have_DP = 0;
  int have_DQ = 0;
  int have_QP = 0;
#endif /* ! MBEDTLS_RSA_NO_CRT */
  int n_missing = 0;
  int pq_missing = 0;
  int d_missing = 0;
  int is_pub = 0;
  int is_priv = 0;

  have_N = (mbedtls_mpi_cmp_int(&ctx->N, 0));
  have_P = (mbedtls_mpi_cmp_int(&ctx->P, 0));
  have_Q = (mbedtls_mpi_cmp_int(&ctx->Q, 0));
  have_D = (mbedtls_mpi_cmp_int(&ctx->D, 0));
  have_E = (mbedtls_mpi_cmp_int(&ctx->E, 0));

#if !defined(MBEDTLS_RSA_NO_CRT)
  have_DP = (mbedtls_mpi_cmp_int(&ctx->DP, 0) != 0);
  have_DQ = (mbedtls_mpi_cmp_int(&ctx->DQ, 0) != 0);
  have_QP = (mbedtls_mpi_cmp_int(&ctx->QP, 0) != 0);
#endif /* ! MBEDTLS_RSA_NO_CRT */

  /*
   * Check whether provided parameters are enough
   * to deduce all others. The following incomplete
   * parameter sets for private keys are supported:
   *
   * (1) P, Q missing.
   * (2) D and potentially N missing.
   *
   */

  n_missing  = ((have_P != 0) && (have_Q != 0) && (have_D != 0) && (have_E != 0)) ? 1 : 0;
  pq_missing = ((have_N != 0) && !(have_P != 0) && !(have_Q != 0) && (have_D != 0) && (have_E != 0)) ? 1 : 0;
  d_missing  = ((have_P != 0) && (have_Q != 0) && !(have_D != 0) && (have_E != 0)) ? 1 : 0;
  is_pub     = ((have_N != 0) && !(have_P != 0) && !(have_Q != 0) && !(have_D != 0) && (have_E != 0)) ? 1 : 0;

  /* These three alternatives are mutually exclusive */
  is_priv = ((n_missing != 0) || (pq_missing != 0) || (d_missing != 0)) ? 1 : 0;

  if (!(is_priv != 0) && !(is_pub != 0))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /*
   * Step 1: Deduce N if P, Q are provided.
   */

  if (!(have_N != 0) && (have_P != 0) && (have_Q != 0))
  {
    ret = mbedtls_mpi_mul_mpi(&ctx->N, &ctx->P,
                              &ctx->Q);
    if (ret != 0)
    {
      return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }

    ctx->len = mbedtls_mpi_size(&ctx->N);
  }

  /*
   * Step 2: Deduce and verify all remaining core parameters.
   */

  if (pq_missing != 0)
  {
    ret = mbedtls_rsa_deduce_primes(&ctx->N, &ctx->E, &ctx->D,
                                    &ctx->P, &ctx->Q);
    if (ret != 0)
    {
      return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }

  }
  else if (d_missing != 0)
  {
    ret = mbedtls_rsa_deduce_private_exponent(&ctx->P,
                                              &ctx->Q,
                                              &ctx->E,
                                              &ctx->D);
    if (ret  != 0)
    {
      return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }
  }
  else
  {
    /* No action required. */
  }
  /*
   * Step 3: Deduce all additional parameters specific
   *         to our current RSA implementation.
   */
#if !defined(MBEDTLS_RSA_NO_CRT)
  if (is_priv && !(have_DP && have_DQ && have_QP))
  {
    ret = mbedtls_rsa_deduce_crt(&ctx->P,  &ctx->Q,  &ctx->D,
                                 &ctx->DP, &ctx->DQ, &ctx->QP);
    if (ret != 0)
    {
      return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }
  }
#endif /* MBEDTLS_RSA_NO_CRT */

  /*
   * Step 3: Basic sanity checks
   */

  return rsa_check_context(ctx, is_priv, 1);
}

int mbedtls_rsa_export_raw(const mbedtls_rsa_context *ctx,
                           unsigned char *N, size_t N_len,
                           unsigned char *P, size_t P_len,
                           unsigned char *Q, size_t Q_len,
                           unsigned char *D, size_t D_len,
                           unsigned char *E, size_t E_len)
{
  int ret = 0;
  int is_priv = 0;
  int mpi_n = mbedtls_mpi_cmp_int(&ctx->N, 0);
  int mpi_p = mbedtls_mpi_cmp_int(&ctx->P, 0);
  int mpi_q = mbedtls_mpi_cmp_int(&ctx->Q, 0);
  int mpi_d = mbedtls_mpi_cmp_int(&ctx->D, 0);
  int mpi_e = mbedtls_mpi_cmp_int(&ctx->E, 0);

  /* Check if key is private or public */
  is_priv =
    ((mpi_n != 0)
     && (mpi_p != 0)
     && (mpi_q != 0)
     && (mpi_d != 0)
     && (mpi_e != 0)) ? 1 : 0;

  if (is_priv == 0)
  {
    /* If we're trying to export private parameters for a public key,
     * something must be wrong. */
    if ((P != NULL) || (Q != NULL) || (D != NULL))
    {
      return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

  }

  if (N != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_write_binary(&ctx->N, N, N_len));
  }

  if (P != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_write_binary(&ctx->P, P, P_len));
  }

  if (Q != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_write_binary(&ctx->Q, Q, Q_len));
  }

  if (D != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_write_binary(&ctx->D, D, D_len));
  }

  if (E != NULL)
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_write_binary(&ctx->E, E, E_len));
  }

cleanup:

  return ret;
}

int mbedtls_rsa_export(const mbedtls_rsa_context *ctx,
                       mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q,
                       mbedtls_mpi *D, mbedtls_mpi *E)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  int is_priv = 0;
  int cmp_n = mbedtls_mpi_cmp_int(&ctx->N, 0);
  int cmp_p = mbedtls_mpi_cmp_int(&ctx->P, 0);
  int cmp_q = mbedtls_mpi_cmp_int(&ctx->Q, 0);
  int cmp_d = mbedtls_mpi_cmp_int(&ctx->D, 0);
  int cmp_e = mbedtls_mpi_cmp_int(&ctx->E, 0);

  /* Check if key is private or public */
  is_priv =
    ((cmp_n != 0)
     && (cmp_p != 0)
     && (cmp_q != 0)
     && (cmp_d != 0)
     && (cmp_e != 0)) ? 1 : 0;

  if (is_priv == 0)
  {
    /* If we're trying to export private parameters for a public key,
     * something must be wrong. */
    if ((P != NULL) || (Q != NULL) || (D != NULL))
    {
      return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

  }

  /* Export all requested core parameters. */

  if (N != NULL)
  {
    ret = mbedtls_mpi_copy(N, &ctx->N);
    if (ret != 0)
    {
      return ret;
    }
  }
  if (P != NULL)
  {
    ret = mbedtls_mpi_copy(P, &ctx->P);
    if (ret != 0)
    {
      return ret;
    }
  }
  if (Q != NULL)
  {
    ret = mbedtls_mpi_copy(Q, &ctx->Q);
    if (ret != 0)
    {
      return ret;
    }
  }
  if (D != NULL)
  {
    ret = mbedtls_mpi_copy(D, &ctx->D);
    if (ret != 0)
    {
      return ret;
    }
  }
  if (E != NULL)
  {
    ret = mbedtls_mpi_copy(E, &ctx->E);
    if (ret != 0)
    {
      return ret;
    }
  }

  return 0;
}

/**
  * @brief Export CRT parameters.
  *
  * @details
  * This must also be implemented if CRT is not used, in order to be able to
  * write DER encoded RSA keys. The helper function mbedtls_rsa_deduce_crt
  * can be used in this case.
  */
int mbedtls_rsa_export_crt(const mbedtls_rsa_context *ctx,
                           mbedtls_mpi *DP, mbedtls_mpi *DQ, mbedtls_mpi *QP)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  int is_priv = 0;
  int cmp_n = mbedtls_mpi_cmp_int(&ctx->N, 0);
  int cmp_p = mbedtls_mpi_cmp_int(&ctx->P, 0);
  int cmp_q = mbedtls_mpi_cmp_int(&ctx->Q, 0);
  int cmp_d = mbedtls_mpi_cmp_int(&ctx->D, 0);
  int cmp_e = mbedtls_mpi_cmp_int(&ctx->E, 0);

  /* Check if key is private or public */
  is_priv =
    ((cmp_n != 0)
     && (cmp_p != 0)
     && (cmp_q != 0)
     && (cmp_d != 0)
     && (cmp_e != 0)) ? 1 : 0;

  if (is_priv == 0)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

#if !defined(MBEDTLS_RSA_NO_CRT)
  /* Export all requested blinding parameters. */
  if ((DP != NULL && (ret = mbedtls_mpi_copy(DP, &ctx->DP)) != 0)
      || (DQ != NULL && (ret = mbedtls_mpi_copy(DQ, &ctx->DQ)) != 0)
      || (QP != NULL && (ret = mbedtls_mpi_copy(QP, &ctx->QP)) != 0))
  {
    return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
  }
#else
  ret = mbedtls_rsa_deduce_crt(&ctx->P, &ctx->Q, &ctx->D,
                               DP, DQ, QP);
  if (ret != 0)
  {
    return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
  }
#endif /* !MBEDTLS_RSA_NO_CRT */

  return 0;
}

/**
  * @brief Initialize an RSA context.
  */
void mbedtls_rsa_init(mbedtls_rsa_context *ctx)
{
  (void)memset(ctx, 0, sizeof(mbedtls_rsa_context));

  ctx->padding = MBEDTLS_RSA_PKCS_V15;
  ctx->hash_id = (int)MBEDTLS_MD_NONE;

#if defined(MBEDTLS_THREADING_C)
  /* Set ctx->ver to nonzero to indicate that the mutex has been
   * initialized and will need to be freed. */
  ctx->ver = 1;
  mbedtls_mutex_init(&ctx->mutex);
#endif /* MBEDTLS_THREADING_C */
}

/**
  * @brief Set padding for an existing RSA context.
  */
int mbedtls_rsa_set_padding(mbedtls_rsa_context *ctx, int padding,
                            mbedtls_md_type_t hash_id)
{
  switch (padding)
  {
#if defined(MBEDTLS_PKCS1_V15)
    case MBEDTLS_RSA_PKCS_V15:
      break;
#endif /*MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
    case MBEDTLS_RSA_PKCS_V21:
      break;
#endif /* MBEDTLS_PKCS1_V21 */
    default:
      return MBEDTLS_ERR_RSA_INVALID_PADDING;
      break;
  }

#if defined(MBEDTLS_PKCS1_V21)
  if ((padding == MBEDTLS_RSA_PKCS_V21)
      && (hash_id != MBEDTLS_MD_NONE))
  {
    /* Just make sure this hash is supported in this build. */
    if (mbedtls_md_info_from_type(hash_id) == NULL)
    {
      return MBEDTLS_ERR_RSA_INVALID_PADDING;
    }
  }
#endif /* MBEDTLS_PKCS1_V21 */

  ctx->padding = padding;
  ctx->hash_id = (int)hash_id;

  return 0;
}

/**
  * @brief Get padding mode of initialized RSA context.
  */
int mbedtls_rsa_get_padding_mode(const mbedtls_rsa_context *ctx)
{
  return ctx->padding;
}

/**
  * @brief Get hash identifier of mbedtls_md_type_t type.
  */
int mbedtls_rsa_get_md_alg(const mbedtls_rsa_context *ctx)
{
  return ctx->hash_id;
}

/**
  * @brief Get length in bits of RSA modulus.
  */
size_t mbedtls_rsa_get_bitlen(const mbedtls_rsa_context *ctx)
{
  return mbedtls_mpi_bitlen(&ctx->N);
}

/**
  * @brief Get length in bytes of RSA modulus.
  */
size_t mbedtls_rsa_get_len(const mbedtls_rsa_context *ctx)
{
  return ctx->len;
}

#if defined(MBEDTLS_GENPRIME)

/**
  * @brief Generate an RSA key pair.
  *
  * @details
  * This generation method follows the RSA key pair generation procedure of
  * FIPS 186-4 if 2^16 < exponent < 2^256 and nbits = 2048 or nbits = 3072.
  */
int mbedtls_rsa_gen_key(mbedtls_rsa_context *ctx,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng,
                        unsigned int nbits, int exponent)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  mbedtls_mpi H;
  mbedtls_mpi G;
  mbedtls_mpi L;

  int prime_quality = 0;

  /*
   * If the modulus is 1024 bit long or shorter, then the security strength of
   * the RSA algorithm is less than or equal to 80 bits and therefore an error
   * rate of 2^-80 is sufficient.
   */
  if (nbits > 1024)
  {
    prime_quality = MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR;
  }

  mbedtls_mpi_init(&H);
  mbedtls_mpi_init(&G);
  mbedtls_mpi_init(&L);

  if (exponent < 3 || nbits % 2 != 0)
  {
    ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    goto cleanup;
  }

  if (nbits < MBEDTLS_RSA_GEN_KEY_MIN_BITS)
  {
    ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    goto cleanup;
  }

  /*
   * find primes P and Q with Q < P so that:
   * 1.  |P-Q| > 2^( nbits / 2 - 100 )
   * 2.  GCD( E, (P-1)*(Q-1) ) == 1
   * 3.  E^-1 mod LCM(P-1, Q-1) > 2^( nbits / 2 )
   */
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_lset(&ctx->E, exponent));

  do
  {
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_gen_prime(&ctx->P, nbits >> 1,
                                                  prime_quality, f_rng, p_rng));

    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_gen_prime(&ctx->Q, nbits >> 1,
                                                  prime_quality, f_rng, p_rng));

    /* make sure the difference between p and q is not too small
       (FIPS 186-4 par. B.3.3 step 5.4) */
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_sub_mpi(&H, &ctx->P, &ctx->Q));
    if (mbedtls_mpi_bitlen(&H) <=
        ((nbits >= 200) ? ((nbits >> 1) - 99) : 0))
    {
      continue;
    }

    /* not required by any standards, but some users rely
       on the fact that P > Q */
    if (H.s < 0)
    {
      mbedtls_mpi_swap(&ctx->P, &ctx->Q);
    }

    /* Temporarily replace P,Q by P-1, Q-1 */
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_sub_int(&ctx->P, &ctx->P, 1));
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_sub_int(&ctx->Q, &ctx->Q, 1));
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_mul_mpi(&H, &ctx->P, &ctx->Q));

    /* check GCD( E, (P-1)*(Q-1) ) == 1
      (FIPS 186-4 par. B.3.1 criterion 2(a)) */
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_gcd(&G, &ctx->E, &H));
    if (mbedtls_mpi_cmp_int(&G, 1) != 0)
    {
      continue;
    }

    /* compute smallest possible D = E^-1 mod LCM(P-1, Q-1)
       (FIPS 186-4 par. B.3.1 criterion 3(b)) */
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_gcd(&G, &ctx->P, &ctx->Q));
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_div_mpi(&L, NULL, &H, &G));
    MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_inv_mod(&ctx->D, &ctx->E, &L));

    /* (FIPS 186-4 par. B.3.1 criterion 3(a)) */
    if (mbedtls_mpi_bitlen(&ctx->D) <= ((nbits + 1) / 2))
    {
      continue;
    }

    break;
  } while (1);

  /* Restore P,Q */
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_add_int(&ctx->P,  &ctx->P, 1));
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_add_int(&ctx->Q,  &ctx->Q, 1));

  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_mul_mpi(&ctx->N, &ctx->P, &ctx->Q));

  ctx->len = mbedtls_mpi_size(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
  /*
   * DP = D mod (P - 1)
   * DQ = D mod (Q - 1)
   * QP = Q^-1 mod P
   */
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_rsa_deduce_crt(&ctx->P, &ctx->Q, &ctx->D,
                                                 &ctx->DP, &ctx->DQ, &ctx->QP));
#endif /* !MBEDTLS_RSA_NO_CRT */

  /* Double-check */
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_rsa_check_privkey(ctx));

cleanup:

  mbedtls_mpi_free(&H);
  mbedtls_mpi_free(&G);
  mbedtls_mpi_free(&L);

  if (ret != 0)
  {
    mbedtls_rsa_free(ctx);

    if ((-ret & ~0x7f) == 0)
    {
      ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_KEY_GEN_FAILED, ret);
    }
    return ret;
  }

  return 0;
}

#endif /* MBEDTLS_GENPRIME */

/**
  * @brief Check a public RSA key.
  */
int mbedtls_rsa_check_pubkey(const mbedtls_rsa_context *ctx)
{
  int mpi_get_bit = mbedtls_mpi_get_bit(&ctx->E, 0);
  unsigned int mpi_bitlen = mbedtls_mpi_bitlen(&ctx->E);
  int cmp_mpi = mbedtls_mpi_cmp_mpi(&ctx->E, &ctx->N);
  if (rsa_check_context(ctx, 0 /* public */, 0 /* no blinding */) != 0)
  {
    return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
  }

  if (mbedtls_mpi_bitlen(&ctx->N) < 128U)
  {
    return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
  }

  if ((mpi_get_bit == 0)
      || (mpi_bitlen     < 2U)
      || (cmp_mpi >= 0))
  {
    return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
  }

  return 0;
}

/**
  * @brief Check for the consistency of all fields in an RSA private key context.
  */
int mbedtls_rsa_check_privkey(const mbedtls_rsa_context *ctx)
{
  int check_pubkey = mbedtls_rsa_check_pubkey(ctx);
  int check_context = rsa_check_context(ctx, 1 /* private */, 1 /* blinding */);
  if ((check_pubkey != 0) || (check_context != 0))
  {
    return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
  }

  if (mbedtls_rsa_validate_params(&ctx->N, &ctx->P, &ctx->Q,
                                  &ctx->D, &ctx->E, NULL, NULL) != 0)
  {
    return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
  }

#if !defined(MBEDTLS_RSA_NO_CRT)
  else if (mbedtls_rsa_validate_crt(&ctx->P, &ctx->Q, &ctx->D,
                                    &ctx->DP, &ctx->DQ, &ctx->QP) != 0)
  {
    return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
  }
#endif /* !MBEDTLS_RSA_NO_CRT */

  return 0;
}

/**
  * @brief Check if contexts holding a public and private key match
  */
int mbedtls_rsa_check_pub_priv(const mbedtls_rsa_context *pub,
                               const mbedtls_rsa_context *prv)
{
  int check_pubkey = mbedtls_rsa_check_pubkey(pub);
  int check_privkey = mbedtls_rsa_check_privkey(prv);
  int mpi_n = mbedtls_mpi_cmp_mpi(&pub->N, &prv->N);
  int mpi_e = mbedtls_mpi_cmp_mpi(&pub->E, &prv->E);

  if ((check_pubkey  != 0) || (check_privkey != 0))
  {
    return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
  }

  if ((mpi_n != 0) || (mpi_e  != 0))
  {
    return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
  }

  return 0;
}

#if defined(MBEDTLS_PKCS1_V21)
/**
  * @brief Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
  */
int mbedtls_rsa_rsaes_oaep_encrypt(mbedtls_rsa_context *ctx,
                                   int (*f_rng)(void *, unsigned char *, size_t),
                                   void *p_rng,
                                   const unsigned char *label, size_t label_len,
                                   size_t ilen,
                                   const unsigned char *input,
                                   unsigned char *output)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED; /* Final return value */
  cmox_rsa_retval_t retval = 0;         /* STCryptoLib return value */
  cmox_rsa_key_t rsa_key = {0};         /* Rsa key with STCryptoLib format */
  uint8_t a_modulus[ST_MOD_MAX_SIZE / 8] = {0}; /* Modulus as array */
  uint8_t a_public_exp[PUBLIC_EXP_LEN] = {0};  /* Public exponent as array */
  uint8_t *p_working_buffer = NULL; /* RSA working buffer for STCryptoLib */
  uint16_t buff_size = ST_BUFFER_SIZE_PKCS1_V21; /* Max space needed by STCryptoLib */
  size_t computed_size = 0;         /* Size of cipher text generated */
  size_t rlen = 0;                  /* Actual random length */
  unsigned int hlen = 0;            /* Hash length */
  cmox_rsa_pkcs1v22_hash_t p_hash_id = 0; /* Hash id for cmox operation */
  /* The random use the output buffer for size optimization */
  unsigned char *p = output;

  if (f_rng == NULL)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /* Get the hash id */
  hlen = mbedtls_md_get_size_from_type((mbedtls_md_type_t) ctx->hash_id);
  if (hlen == 0U)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  p_hash_id = rsa_alt_hashId_1v22((mbedtls_md_type_t) ctx->hash_id, hlen);

  /* Allocate the working buffer for the STCryptoLib */
  p_working_buffer = mbedtls_calloc(buff_size, sizeof(uint8_t));
  if (p_working_buffer == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Construct the RSA context */
  cmox_rsa_construct(&ctx->rsa_ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PUBLIC,
                     p_working_buffer, buff_size);

  /* Use mbedtls_mpi_size for the size and not sizeof(modulus) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->N) > sizeof(a_modulus))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->N, a_modulus,
                                 mbedtls_mpi_size(&ctx->N));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(E) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->E) > sizeof(a_public_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->E, a_public_exp,
                                 mbedtls_mpi_size(&ctx->E));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the regular public key representation */
  retval = cmox_rsa_setKey(&rsa_key, a_modulus, mbedtls_mpi_size(&ctx->N),
                           a_public_exp, mbedtls_mpi_size(&ctx->E));
  if (retval != CMOX_RSA_SUCCESS)
  {
    ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    goto exit;
  }

  /* Calculate the random length : k - mlen - 3, cf RFC8017 */
  rlen = ctx->len - 3U - ilen;

  /* Generate the random */
  ret = f_rng(p_rng, p, rlen);
  if (ret != 0)
  {
    ret = MBEDTLS_ERR_RSA_RNG_FAILED + ret;
    goto exit;
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v22_encrypt(&ctx->rsa_ctx, &rsa_key, input, ilen,
                                     p_hash_id, p, rlen, label, label_len,
                                     output, &computed_size);
  ret = rsa_mbed_return_value(retval);

exit:
  mbedtls_free(p_working_buffer);
  return ret;
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/**
  * @brief Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
  */
int mbedtls_rsa_rsaes_pkcs1_v15_encrypt(mbedtls_rsa_context *ctx,
                                        int (*f_rng)(void *, unsigned char *, size_t),
                                        void *p_rng, size_t ilen,
                                        const unsigned char *input,
                                        unsigned char *output)
{

  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED; /* Final return value */
  cmox_rsa_retval_t retval = 0;          /* STCryptoLib return value */
  cmox_rsa_key_t rsa_key = {0};          /* Rsa key with STCryptoLib format */
  uint8_t a_modulus[ST_MOD_MAX_SIZE / 8] = {0}; /* Modulus as array */
  uint8_t a_public_exp[PUBLIC_EXP_LEN] = {0};  /* Public exponent as array */
  uint8_t *p_working_buffer;            /* RSA working buffer */
  uint16_t buff_size = ST_BUFFER_SIZE_PKCS1_V15;  /* Max space needed by STCryptoLib */
  size_t computed_size = 0;             /* Size of cipher text generated */
  size_t rlen = 0;                      /* Actual random length */
  /* The random use the output buffer for size optimization */
  unsigned char *p = output;


  if (f_rng == NULL)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /* Allocate the working buffer for the STCryptoLib */
  p_working_buffer = mbedtls_calloc(buff_size, sizeof(uint8_t));
  if (p_working_buffer == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Construct the RSA context */
  cmox_rsa_construct(&ctx->rsa_ctx, CMOX_RSA_MATH_FUNCS,
                     CMOX_MODEXP_PUBLIC, p_working_buffer, buff_size);

  /* Use mbedtls_mpi_size for the size and not sizeof(modulus)
     for avoid zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->N) > sizeof(a_modulus))
  {
    mbedtls_free(p_working_buffer);
    return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
  }
  ret = mbedtls_mpi_write_binary(&ctx->N, a_modulus,
                                 mbedtls_mpi_size(&ctx->N));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(E) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->E) > sizeof(a_public_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->E, a_public_exp,
                                 mbedtls_mpi_size(&ctx->E));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the regular public key representation */
  retval = cmox_rsa_setKey(&rsa_key, a_modulus, mbedtls_mpi_size(&ctx->N),
                           a_public_exp, mbedtls_mpi_size(&ctx->E));
  if (retval != CMOX_RSA_SUCCESS)
  {
    ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    goto exit;
  }

  /* Calculate the random length : k - mlen - 3, cf RFC8017 7.2.1 */
  rlen = ctx->len - 3U - ilen;
  /* Generate an octet string PS consisting of pseudo-randomly generated
     nonzero octets */
  while (rlen > 0U)
  {
    rlen--;
    do
    {
      ret = f_rng(p_rng, p, 1);
    } while ((*p == 0U) && (ret == 0));

    /* Check if RNG failed to generate data */
    if (ret != 0)
    {
      ret = MBEDTLS_ERR_RSA_RNG_FAILED + ret;
      goto exit;
    }
    p++;
  }
  rlen--;

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v15_encrypt(&ctx->rsa_ctx, &rsa_key, input, ilen,
                                     p, rlen, output, &computed_size);
  ret = rsa_mbed_return_value(retval);

exit:
  mbedtls_free(p_working_buffer);
  return ret;
}
#endif /* MBEDTLS_PKCS1_V15 */

/**
  * @brief Add the message padding, then do an RSA operation.
  */
int mbedtls_rsa_pkcs1_encrypt(mbedtls_rsa_context *ctx,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng, size_t ilen,
                              const unsigned char *input,
                              unsigned char *output)
{
  switch (ctx->padding)
  {
#if defined(MBEDTLS_PKCS1_V15)
    case MBEDTLS_RSA_PKCS_V15:
      return mbedtls_rsa_rsaes_pkcs1_v15_encrypt(ctx, f_rng, p_rng,
                                                 ilen, input, output);
      break;
#endif /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
    case MBEDTLS_RSA_PKCS_V21:
      return mbedtls_rsa_rsaes_oaep_encrypt(ctx, f_rng, p_rng, NULL, 0,
                                            ilen, input, output);
      break;
#endif /* MBEDTLS_PKCS1_V21 */

    default:
      return MBEDTLS_ERR_RSA_INVALID_PADDING;
      break;
  }
}

#if defined(MBEDTLS_PKCS1_V21)
/**
  * @brief Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
  */
int mbedtls_rsa_rsaes_oaep_decrypt(mbedtls_rsa_context *ctx,
                                   int (*f_rng)(void *, unsigned char *, size_t),
                                   void *p_rng,
                                   const unsigned char *label, size_t label_len,
                                   size_t *olen,
                                   const unsigned char *input,
                                   unsigned char *output,
                                   size_t output_max_len)
{
  (void) f_rng;
  (void) p_rng;
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED; /* Final return value */
  cmox_rsa_retval_t retval = 0;          /* STCryptoLib return value */
  cmox_rsa_key_t rsa_key = {0};          /* Rsa key with STCryptoLib format */
  uint8_t *p_working_buffer = NULL;  /* RSA working buffer */
  uint16_t buff_size = ST_BUFFER_SIZE_PKCS1_V21; /* Max space needed by STCryptoLib */
  uint8_t *p_temp_output = NULL;     /* Plaintext before size check control */
  unsigned int hlen = 0;             /* Hash length */
  cmox_rsa_pkcs1v22_hash_t p_hash_id = 0;     /* Hash id for cmox operation */
#if defined(MBEDTLS_RSA_NO_CRT)
  uint8_t a_modulus[ST_MOD_MAX_SIZE / 8] = {0};       /* Modulus as array */
  uint8_t a_private_exp[ST_MOD_MAX_SIZE / 8] = {0};   /* Priv key as array */
#else
  uint8_t p_prime_exponent[ST_MOD_MAX_SIZE / 16u] = {0}; /* Half modulus size */
  uint8_t q_prime_exponent[ST_MOD_MAX_SIZE / 16u] = {0}; /* Half modulus size */
  uint8_t p_prime[ST_MOD_MAX_SIZE / 16u] = {0};        /* Half modulus size */
  uint8_t q_prime[ST_MOD_MAX_SIZE / 16u] = {0};        /* Half modulus size */
  uint8_t coefficient[ST_MOD_MAX_SIZE / 16u] = {0};    /* Half modulus size */
  uint8_t a_public_exp[PUBLIC_EXP_LEN] = {0}; /* Public exponent as array */
#endif /* MBEDTLS_RSA_NO_CRT */

  /*
   * Parameters sanity checks
   */
  if (ctx->padding != MBEDTLS_RSA_PKCS_V21)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /* Get the hash id */
  hlen = mbedtls_md_get_size_from_type((mbedtls_md_type_t) ctx->hash_id);
  if (hlen == 0U)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  p_hash_id = rsa_alt_hashId_1v22((mbedtls_md_type_t) ctx->hash_id, hlen);

  /* Allocate buffer for holding plaintext. Do no use the output to avoid
     corrupt it if the decrypt fail */
  p_temp_output = mbedtls_calloc(ctx->len, sizeof(uint8_t));
  /* Maximum size of the encoded plaintext is modulus size, see RFC8017 7.2.2
     and the formula EM = 0x00 || 0x02 || PS || 0x00 || M */
  if (p_temp_output == NULL)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /* Allocate the working buffer for the STCryptoLib */
  p_working_buffer = mbedtls_calloc(buff_size, sizeof(uint8_t));
  if (p_working_buffer == NULL)
  {
    mbedtls_free(p_temp_output);
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Construct the RSA context */
  cmox_rsa_construct(&ctx->rsa_ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PRIVATE,
                     p_working_buffer, buff_size);

#if defined(MBEDTLS_RSA_NO_CRT)
  /* Use mbedtls_mpi_size for the size and not sizeof(modulus)
     for avoid zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->N) > sizeof(a_modulus))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->N, a_modulus,
                                 mbedtls_mpi_size(&ctx->N));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(D) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->D) > sizeof(a_private_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->D, a_private_exp,
                                 mbedtls_mpi_size(&ctx->D));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the regular private key representation */
  retval = cmox_rsa_setKey(&rsa_key, a_modulus, mbedtls_mpi_size(&ctx->N),
                           a_private_exp, mbedtls_mpi_size(&ctx->D));
#else
  /* Use mbedtls_mpi_size for the size and not sizeof(DP)
     for avoid zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->DP) > sizeof(p_prime_exponent))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->DP, p_prime_exponent,
                                 mbedtls_mpi_size(&ctx->DP));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(DQ) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->DQ) > sizeof(q_prime_exponent))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->DQ, q_prime_exponent,
                                 mbedtls_mpi_size(&ctx->DQ));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(P) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->P) > sizeof(p_prime))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->P, p_prime,
                                 mbedtls_mpi_size(&ctx->P));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(Q) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->Q) > sizeof(q_prime))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->Q, q_prime,
                                 mbedtls_mpi_size(&ctx->Q));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(E) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->E) > sizeof(a_public_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->E, a_public_exp,
                                 mbedtls_mpi_size(&ctx->E));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(QP) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->QP) > sizeof(coefficient))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->QP, coefficient,
                                 mbedtls_mpi_size(&ctx->QP));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the CRT key representation */
  retval = cmox_rsa_setKeyCRTwithFACM(&rsa_key,
                                      (mbedtls_mpi_size(&ctx->N) * 8),
                                      p_prime_exponent,
                                      mbedtls_mpi_size(&ctx->DP),
                                      q_prime_exponent,
                                      mbedtls_mpi_size(&ctx->DQ),
                                      p_prime, mbedtls_mpi_size(&ctx->P),
                                      q_prime, mbedtls_mpi_size(&ctx->Q),
                                      coefficient,
                                      mbedtls_mpi_size(&ctx->QP),
                                      a_public_exp,
                                      mbedtls_mpi_size(&ctx->E));
#endif /* MBEDTLS_RSA_NO_CRT */

  if (retval != CMOX_RSA_SUCCESS)
  {
    ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    goto exit;
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v22_decrypt(&ctx->rsa_ctx, &rsa_key, input,
                                     ctx->len, p_hash_id, label, label_len,
                                     p_temp_output, olen);

  if (retval == CMOX_RSA_SUCCESS)
  {
    if (*olen > output_max_len)
    {
      /* Copy only data that feed into the buffer for avoid attack */
      (void)memcpy(output, p_temp_output, output_max_len);
      /* Force output to the max allow size for avoid security panic */
      *olen = output_max_len;
      ret = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }
    else
    {
      ret = rsa_mbed_return_value(retval);
      (void)memcpy(output, p_temp_output, *olen);     /* Copy the output */
    }
  }
  else
  {
    /*
     * The only information "leaked" is whether the padding was correct or
     * not (eg, no data is copied if it was not correct). This meets the
     * recommendations in PKCS#1 v2.2: an opponent cannot distinguish
     * between the different error conditions.
     */
    ret = rsa_mbed_return_value(retval);
  }

exit:
  mbedtls_free(p_temp_output);
  mbedtls_free(p_working_buffer);
  return ret;

}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)

/**
  * @brief Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
  */
int mbedtls_rsa_rsaes_pkcs1_v15_decrypt(mbedtls_rsa_context *ctx,
                                        int (*f_rng)(void *, unsigned char *, size_t),
                                        void *p_rng,
                                        size_t *olen,
                                        const unsigned char *input,
                                        unsigned char *output,
                                        size_t output_max_len)
{
  (void) f_rng;
  (void) p_rng;
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED; /* Final return value */
  cmox_rsa_retval_t retval = 0;           /* STCryptoLib return value */
  cmox_rsa_key_t rsa_key = {0};           /* Rsa key with STCryptoLib format */
  uint8_t *p_working_buffer = NULL;   /* RSA working buffer */
  uint16_t buff_size = ST_BUFFER_SIZE_PKCS1_V15;/* Max space needed by STCryptoLib */
  uint8_t *p_temp_output = NULL;      /*Plaintext before size check control */
#if defined(MBEDTLS_RSA_NO_CRT)
  uint8_t a_modulus[ST_MOD_MAX_SIZE / 8] = {0};   /* Modulus as array */
  uint8_t a_private_exp[ST_MOD_MAX_SIZE / 8] = {0}; /* Private key as array */
#else
  uint8_t p_prime_exponent[ST_MOD_MAX_SIZE / 16u] = {0}; /* Half modulus size */
  uint8_t q_prime_exponent[ST_MOD_MAX_SIZE / 16u] = {0}; /* Half modulus size */
  uint8_t p_prime[ST_MOD_MAX_SIZE / 16u] = {0};        /* Half modulus size */
  uint8_t q_prime[ST_MOD_MAX_SIZE / 16u] = {0};        /* Half modulus size */
  uint8_t coefficient[ST_MOD_MAX_SIZE / 16u] = {0};    /* Half modulus size */
  uint8_t a_public_exp[PUBLIC_EXP_LEN] = {0};   /* Public exponent as array */
#endif /* MBEDTLS_RSA_NO_CRT */


  if (ctx->padding != MBEDTLS_RSA_PKCS_V15)
  {
    ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /* Allocate buffer for holding plaintext. Do no use the output to avoid
     corrupt it if the decrypt fail */
  p_temp_output = mbedtls_calloc(ctx->len, sizeof(uint8_t));
  /* Maximum size of the encoded plaintext is modulus size, see RFC8017 7.2.1
     and the formula EM = 0x00 || 0x02 || PS || 0x00 || M */
  if (p_temp_output == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Allocate the working buffer for the STCryptoLib */
  p_working_buffer = mbedtls_calloc(buff_size, sizeof(uint8_t));
  if (p_working_buffer == NULL)
  {
    mbedtls_free(p_temp_output);
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Construct the RSA context */
  cmox_rsa_construct(&ctx->rsa_ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PRIVATE,
                     p_working_buffer, buff_size);


#if defined(MBEDTLS_RSA_NO_CRT)
  /* Use mbedtls_mpi_size for the size and not sizeof(modulus) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->N) > sizeof(a_modulus))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->N, a_modulus,
                                 mbedtls_mpi_size(&ctx->N));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(D) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->D) > sizeof(a_private_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->D, a_private_exp,
                                 mbedtls_mpi_size(&ctx->D));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the regular private key representation */
  retval = cmox_rsa_setKey(&rsa_key, a_modulus, mbedtls_mpi_size(&ctx->N),
                           a_private_exp, mbedtls_mpi_size(&ctx->D));
#else
  /* Use mbedtls_mpi_size for the size and not sizeof(DP) for
     avoid zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->DP) > sizeof(p_prime_exponent))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->DP, p_prime_exponent,
                                 mbedtls_mpi_size(&ctx->DP));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(DQ) for
     avoid zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->DQ) > sizeof(q_prime_exponent))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->DQ, q_prime_exponent,
                                 mbedtls_mpi_size(&ctx->DQ));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(P) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->P) > sizeof(p_prime))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->P, p_prime,
                                 mbedtls_mpi_size(&ctx->P));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(Q) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->Q) > sizeof(q_prime))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->Q, q_prime,
                                 mbedtls_mpi_size(&ctx->Q));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(E) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->E) > sizeof(a_public_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->E, a_public_exp,
                                 mbedtls_mpi_size(&ctx->E));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(QP) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->QP) > sizeof(coefficient))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->QP, coefficient,
                                 mbedtls_mpi_size(&ctx->QP));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the CRT key representation */
  retval = cmox_rsa_setKeyCRTwithFACM(&rsa_key,
                                      (mbedtls_mpi_size(&ctx->N) * 8),
                                      p_prime_exponent,
                                      mbedtls_mpi_size(&ctx->DP),
                                      q_prime_exponent,
                                      mbedtls_mpi_size(&ctx->DQ),
                                      p_prime, mbedtls_mpi_size(&ctx->P),
                                      q_prime, mbedtls_mpi_size(&ctx->Q),
                                      coefficient,
                                      mbedtls_mpi_size(&ctx->QP),
                                      a_public_exp,
                                      mbedtls_mpi_size(&ctx->E));
#endif /* MBEDTLS_RSA_NO_CRT */

  if (retval != CMOX_RSA_SUCCESS)
  {
    ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    goto exit;
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v15_decrypt(&ctx->rsa_ctx, &rsa_key,
                                     input, ctx->len, p_temp_output, olen);

  if (retval == CMOX_RSA_SUCCESS)
  {
    if (*olen > output_max_len)
    {
      /* Copy only data that feed into the buffer for avoid attack */
      (void)memcpy(output, p_temp_output, output_max_len);
      /* Force output to the max allow size for avoid security panic */
      *olen = output_max_len;
      ret = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }
    else
    {
      ret = rsa_mbed_return_value(retval);
      (void)memcpy(output, p_temp_output, *olen);   /* Copy the output */
    }
  }
  else
  {
    ret = rsa_mbed_return_value(retval);
  }

exit:
  mbedtls_free(p_temp_output);
  mbedtls_free(p_working_buffer);
  return ret;
}
#endif /* MBEDTLS_PKCS1_V15 */

/**
  * @brief Do an RSA operation, then remove the message padding.
  */
int mbedtls_rsa_pkcs1_decrypt(mbedtls_rsa_context *ctx,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng,
                              size_t *olen,
                              const unsigned char *input,
                              unsigned char *output,
                              size_t output_max_len)
{
  switch (ctx->padding)
  {
#if defined(MBEDTLS_PKCS1_V15)
    case MBEDTLS_RSA_PKCS_V15:
      return mbedtls_rsa_rsaes_pkcs1_v15_decrypt(ctx, f_rng, p_rng, olen,
                                                 input, output, output_max_len);
      break;
#endif /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
    case MBEDTLS_RSA_PKCS_V21:
      return mbedtls_rsa_rsaes_oaep_decrypt(ctx, f_rng, p_rng, NULL, 0,
                                            olen, input, output,
                                            output_max_len);
      break;
#endif /* MBEDTLS_PKCS1_V21 */

    default:
      return MBEDTLS_ERR_RSA_INVALID_PADDING;
      break;
  }
}

#if defined(MBEDTLS_PKCS1_V21)
/** @cond DOXYGEN_SHOULD_SKIP_THIS */
static int rsa_rsassa_pss_sign_no_mode_check(mbedtls_rsa_context *ctx,
                                             int (*f_rng)(void *, unsigned char *, size_t),
                                             void *p_rng,
                                             mbedtls_md_type_t md_alg,
                                             unsigned int hashlen,
                                             const unsigned char *hash,
                                             int saltlen,
                                             unsigned char *sig)
{
  (void) saltlen;
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED; /* Final return value */
  cmox_rsa_retval_t retval = 0;                  /* STCryptoLib return value */
  size_t computed_size = 0;                      /* Size of computed signature */
  cmox_rsa_pkcs1v22_hash_t p_hash_id = 0;    /* Hash id for cmox operation */
  cmox_rsa_key_t rsa_key = {0};               /* Rsa key with STCryptoLib format */
  unsigned char salt[ST_MD_MAX_SIZE] = {0}; /* Salt */
  size_t slen = 0;                          /* Actual salt length */
  uint8_t *p_working_buffer = NULL;     /* RSA working buffer */
  uint16_t buff_size = ST_BUFFER_SIZE_PKCS1_V21; /* Max space needed by STCryptoLib */
  size_t olen = 0;
  size_t hlen = 0;
  const mbedtls_md_info_t *md_info;     /* Mbed info struct */
#if defined(MBEDTLS_RSA_NO_CRT)
  uint8_t a_modulus[ST_MOD_MAX_SIZE / 8] = {0};   /* Modulus as array */
  uint8_t a_private_exp[ST_MOD_MAX_SIZE / 8] = {0}; /* Same size of modulus */
#else
  uint8_t p_prime_exponent[ST_MOD_MAX_SIZE / 16u] = {0}; /* Half modulus size */
  uint8_t q_prime_exponent[ST_MOD_MAX_SIZE / 16u] = {0}; /* Half modulus size */
  uint8_t p_prime[ST_MOD_MAX_SIZE / 16u] = {0};        /* Half modulus size */
  uint8_t q_prime[ST_MOD_MAX_SIZE / 16u] = {0};        /* Half modulus size */
  uint8_t coefficient[ST_MOD_MAX_SIZE / 16u] = {0};    /* Half modulus size */
  uint8_t a_public_exp[PUBLIC_EXP_LEN] = {0};   /* Public exponent as array */
#endif /* MBEDTLS_RSA_NO_CRT */

  /* Allocate the working buffer for the STCryptoLib */
  p_working_buffer = mbedtls_calloc(buff_size, sizeof(uint8_t));
  if (p_working_buffer == NULL)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /* Output lenfth = signature length = modulus length */
  olen = ctx->len;

  /* Construct the RSA context */
  cmox_rsa_construct(&ctx->rsa_ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PRIVATE,
                     p_working_buffer, buff_size);

  /* Convert mbedtls_md_type_t to cmox_rsa_pkcs1v22_hash_t for the hash id */
  p_hash_id = rsa_alt_hashId_1v22(md_alg, hashlen);

#if defined(MBEDTLS_RSA_NO_CRT)
  /* Use mbedtls_mpi_size for the size and not sizeof(modulus) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->N) > sizeof(a_modulus))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->N, a_modulus,
                                 mbedtls_mpi_size(&ctx->N));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(D) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->D) > sizeof(a_private_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->D, a_private_exp,
                                 mbedtls_mpi_size(&ctx->D));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the regular private key representation */
  retval = cmox_rsa_setKey(&rsa_key, a_modulus, mbedtls_mpi_size(&ctx->N),
                           a_private_exp, mbedtls_mpi_size(&ctx->D));
#else
  /* Use mbedtls_mpi_size for the size and not sizeof(DP) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->DP) > sizeof(p_prime_exponent))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->DP, p_prime_exponent,
                                 mbedtls_mpi_size(&ctx->DP));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(DQ) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->DQ) > sizeof(q_prime_exponent))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->DQ, q_prime_exponent,
                                 mbedtls_mpi_size(&ctx->DQ));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(P) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->P) > sizeof(p_prime))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->P, p_prime,
                                 mbedtls_mpi_size(&ctx->P));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(Q) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->Q) > sizeof(q_prime))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->Q, q_prime,
                                 mbedtls_mpi_size(&ctx->Q));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(E) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->E) > sizeof(a_public_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->E, a_public_exp,
                                 mbedtls_mpi_size(&ctx->E));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(QP) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->QP) > sizeof(coefficient))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->QP, coefficient,
                                 mbedtls_mpi_size(&ctx->QP));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the CRT key representation */
  retval = cmox_rsa_setKeyCRTwithFACM(&rsa_key,
                                      (mbedtls_mpi_size(&ctx->N) * 8),
                                      p_prime_exponent,
                                      mbedtls_mpi_size(&ctx->DP),
                                      q_prime_exponent,
                                      mbedtls_mpi_size(&ctx->DQ),
                                      p_prime, mbedtls_mpi_size(&ctx->P),
                                      q_prime, mbedtls_mpi_size(&ctx->Q),
                                      coefficient,
                                      mbedtls_mpi_size(&ctx->QP),
                                      a_public_exp,
                                      mbedtls_mpi_size(&ctx->E));
#endif /* MBEDTLS_RSA_NO_CRT */

  if (retval != CMOX_RSA_SUCCESS)
  {
    ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    goto exit;
  }

  /* Manage the salt */
  md_info = mbedtls_md_info_from_type((mbedtls_md_type_t) ctx->hash_id);
  if (md_info == NULL)
  {
    ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    goto exit;
  }
  hlen = mbedtls_md_get_size(md_info);

  /* Calculate slen */
  if (olen >= (hlen + hlen + 2U))
  {
    slen = hlen;
  }
  else
  {
    /* Calculate salt length : cf RFC8017 9.1.1 */
    slen = olen - hlen - 2U;
  }

  /* Generate salt of length slen */
  ret = f_rng(p_rng, salt, slen);
  if (ret != 0)
  {
    ret = MBEDTLS_ERR_RSA_RNG_FAILED + ret;
    goto exit;
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v22_sign(&ctx->rsa_ctx, &rsa_key, hash, p_hash_id,
                                  salt, slen, sig, &computed_size);
  ret = rsa_mbed_return_value(retval);

exit:
  mbedtls_free(p_working_buffer);
  return ret;
}
static int rsa_rsassa_pss_sign(mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               int saltlen,
                               unsigned char *sig)
{
  if (ctx->padding != MBEDTLS_RSA_PKCS_V21)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  if ((ctx->hash_id == (int)MBEDTLS_MD_NONE) && (md_alg == MBEDTLS_MD_NONE))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  return rsa_rsassa_pss_sign_no_mode_check(ctx, f_rng, p_rng, md_alg,
                                           hashlen, hash, saltlen, sig);
}
/** @endcond */

int mbedtls_rsa_rsassa_pss_sign_no_mode_check(mbedtls_rsa_context *ctx,
                                              int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng,
                                              mbedtls_md_type_t md_alg,
                                              unsigned int hashlen,
                                              const unsigned char *hash,
                                              unsigned char *sig)
{
  return rsa_rsassa_pss_sign_no_mode_check(ctx, f_rng, p_rng, md_alg,
                                           hashlen, hash, MBEDTLS_RSA_SALT_LEN_ANY, sig);
}

/**
  * @brief Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function with
  * the option to pass in the salt length.
  */
int mbedtls_rsa_rsassa_pss_sign_ext(mbedtls_rsa_context *ctx,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng,
                                    mbedtls_md_type_t md_alg,
                                    unsigned int hashlen,
                                    const unsigned char *hash,
                                    int saltlen,
                                    unsigned char *sig)
{
  return rsa_rsassa_pss_sign(ctx, f_rng, p_rng, md_alg,
                             hashlen, hash, saltlen, sig);
}

/**
  * @brief Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function
  */
int mbedtls_rsa_rsassa_pss_sign(mbedtls_rsa_context *ctx,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng,
                                mbedtls_md_type_t md_alg, unsigned int hashlen,
                                const unsigned char *hash, unsigned char *sig)
{
  return rsa_rsassa_pss_sign(ctx, f_rng, p_rng, md_alg,
                             hashlen, hash, MBEDTLS_RSA_SALT_LEN_ANY, sig);
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/**
  * @brief Do an RSA operation to sign the message digest
  */
int mbedtls_rsa_rsassa_pkcs1_v15_sign(mbedtls_rsa_context *ctx,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void *p_rng, mbedtls_md_type_t md_alg,
                                      unsigned int hashlen, const unsigned char *hash,
                                      unsigned char *sig)
{
  (void) f_rng;
  (void) p_rng;
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED; /* Final return value */
  cmox_rsa_retval_t retval = 0;                    /* STCryptoLib return value */
  size_t computed_size = 0;                        /* Size of computed signature */
  cmox_rsa_pkcs1v15_hash_t p_hash_id = 0;          /* Hash id for cmox operation */
  cmox_rsa_key_t rsa_key = {0};                    /* Rsa key with STCryptoLib format */
  uint8_t *p_working_buffer = NULL;                /* RSA working buffer */
  uint16_t buff_size = ST_BUFFER_SIZE_PKCS1_V15;   /* Max space needed by STCryptoLib */
#if defined(MBEDTLS_RSA_NO_CRT)
  uint8_t a_modulus[ST_MOD_MAX_SIZE / 8] = {0};     /* Modulus as array */
  uint8_t a_private_exp[ST_MOD_MAX_SIZE / 8] = {0}; /* Private key as array */
#else
  uint8_t p_prime_exponent[ST_MOD_MAX_SIZE / 16u] = {0}; /* Half modulus size */
  uint8_t q_prime_exponent[ST_MOD_MAX_SIZE / 16u] = {0}; /* Half modulus size */
  uint8_t p_prime[ST_MOD_MAX_SIZE / 16u] = {0};          /* Half modulus size */
  uint8_t q_prime[ST_MOD_MAX_SIZE / 16u] = {0};          /* Half modulus size */
  uint8_t coefficient[ST_MOD_MAX_SIZE / 16u] = {0};      /* Half modulus size */
  uint8_t a_public_exp[PUBLIC_EXP_LEN] = {0};            /* Public exponent as array */
#endif /* MBEDTLS_RSA_NO_CRT */


  if (ctx->padding != MBEDTLS_RSA_PKCS_V15)
  {
    ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /* Allocate the working buffer for the STCryptoLib */
  p_working_buffer = mbedtls_calloc(buff_size, sizeof(uint8_t));
  if (p_working_buffer == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Construct the RSA context */
  cmox_rsa_construct(&ctx->rsa_ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PRIVATE,
                     p_working_buffer, buff_size);

  /* Convert mbedtls_md_type_t to cmox_rsa_pkcs1v15_hash_t for the hash id */
  p_hash_id = rsa_alt_hashId_1v15(md_alg, hashlen);

#if defined(MBEDTLS_RSA_NO_CRT)
  /* Use mbedtls_mpi_size for the size and not sizeof(modulus) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->N) > sizeof(a_modulus))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->N, a_modulus,
                                 mbedtls_mpi_size(&ctx->N));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(D) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->D) > sizeof(a_private_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->D, a_private_exp,
                                 mbedtls_mpi_size(&ctx->D));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the regular private key representation */
  retval = cmox_rsa_setKey(&rsa_key, a_modulus, mbedtls_mpi_size(&ctx->N),
                           a_private_exp, mbedtls_mpi_size(&ctx->D));
#else
  /* Use mbedtls_mpi_size for the size and not sizeof(DP) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->DP) > sizeof(p_prime_exponent))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->DP, p_prime_exponent,
                                 mbedtls_mpi_size(&ctx->DP));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(DQ) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->DQ) > sizeof(q_prime_exponent))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->DQ, q_prime_exponent,
                                 mbedtls_mpi_size(&ctx->DQ));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(P) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->P) > sizeof(p_prime))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->P, p_prime,
                                 mbedtls_mpi_size(&ctx->P));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(Q) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->Q) > sizeof(q_prime))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->Q, q_prime,
                                 mbedtls_mpi_size(&ctx->Q));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(E) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->E) > sizeof(a_public_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->E, a_public_exp,
                                 mbedtls_mpi_size(&ctx->E));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(QP) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->QP) > sizeof(coefficient))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->QP, coefficient,
                                 mbedtls_mpi_size(&ctx->QP));
  if (ret != 0)
  {
    goto exit;
  }

  /* Fill in RSA key structure using the CRT key representation */
  retval = cmox_rsa_setKeyCRTwithFACM(&rsa_key,
                                      (mbedtls_mpi_size(&ctx->N) * 8),
                                      p_prime_exponent,
                                      mbedtls_mpi_size(&ctx->DP),
                                      q_prime_exponent,
                                      mbedtls_mpi_size(&ctx->DQ),
                                      p_prime, mbedtls_mpi_size(&ctx->P),
                                      q_prime, mbedtls_mpi_size(&ctx->Q),
                                      coefficient,
                                      mbedtls_mpi_size(&ctx->QP),
                                      a_public_exp,
                                      mbedtls_mpi_size(&ctx->E));
#endif /* MBEDTLS_RSA_NO_CRT */

  if (retval != CMOX_RSA_SUCCESS)
  {
    ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    goto exit;
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v15_sign(&ctx->rsa_ctx, &rsa_key, hash, p_hash_id,
                                  sig, &computed_size);
  ret = rsa_mbed_return_value(retval);

exit:
  mbedtls_free(p_working_buffer);
  return ret;
}
#endif /* MBEDTLS_PKCS1_V15 */

/**
  * @brief Do an RSA operation to sign the message digest
  */
int mbedtls_rsa_pkcs1_sign(mbedtls_rsa_context *ctx,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng,
                           mbedtls_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           unsigned char *sig)
{
  if (((md_alg != MBEDTLS_MD_NONE) || (hashlen != 0U)) && (hash == NULL))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  switch (ctx->padding)
  {
#if defined(MBEDTLS_PKCS1_V15)
    case MBEDTLS_RSA_PKCS_V15:
      return mbedtls_rsa_rsassa_pkcs1_v15_sign(ctx, f_rng, p_rng, md_alg,
                                               hashlen, hash, sig);
      break;
#endif /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
    case MBEDTLS_RSA_PKCS_V21:
      return mbedtls_rsa_rsassa_pss_sign(ctx, f_rng, p_rng, md_alg,
                                         hashlen, hash, sig);
      break;
#endif /* MBEDTLS_PKCS1_V21 */

    default:
      return MBEDTLS_ERR_RSA_INVALID_PADDING;
      break;
  }
}

#if defined(MBEDTLS_PKCS1_V21)
/**
  * @brief Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function
  */
int mbedtls_rsa_rsassa_pss_verify_ext(mbedtls_rsa_context *ctx,
                                      mbedtls_md_type_t md_alg,
                                      unsigned int hashlen,
                                      const unsigned char *hash,
                                      mbedtls_md_type_t mgf1_hash_id,
                                      int expected_salt_len,
                                      const unsigned char *sig)
{
  (void) mgf1_hash_id;
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED; /* Final return value */
  cmox_rsa_retval_t retval = 0;              /* STCryptoLib return value */
  cmox_rsa_pkcs1v22_hash_t p_hash_id = 0;    /* Hash id for cmox operation */
  cmox_rsa_key_t rsa_key = {0};              /* Rsa key with STCryptoLib format */
  uint8_t a_modulus[ST_MOD_MAX_SIZE / 8] = {0}; /* Modulus as array */
  uint8_t a_public_exp[PUBLIC_EXP_LEN] = {0};  /* Public exponent as array */
  uint8_t *p_working_buffer = NULL;            /* RSA working buffer */
  uint16_t buff_size = ST_BUFFER_SIZE_PKCS1_V21;/* Max space needed by STCryptoLib */
  uint32_t fault_check = CMOX_RSA_AUTH_FAIL;   /* Fault check variable */
  uint32_t sig_len = 0;                        /* Theoretical signature length */

  if (ctx->padding != MBEDTLS_RSA_PKCS_V21)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /* Allocate the working buffer for the STCryptoLib */
  p_working_buffer = mbedtls_calloc(buff_size, sizeof(uint8_t));
  if (p_working_buffer == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Construct the RSA context */
  cmox_rsa_construct(&ctx->rsa_ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PUBLIC,
                     p_working_buffer, buff_size);

  /* Convert mbedtls_md_type_t to cmox_rsa_pkcs1v22_hash_t for the hash id */
  p_hash_id = rsa_alt_hashId_1v22(md_alg, hashlen);

  /* Use mbedtls_mpi_size for the size and not sizeof(modulus) for
     avoid zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->N) > sizeof(a_modulus))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->N, a_modulus,
                                 mbedtls_mpi_size(&ctx->N));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(E) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->E) > sizeof(a_public_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->E, a_public_exp,
                                 mbedtls_mpi_size(&ctx->E));
  if (ret != 0)
  {
    goto exit;
  }

  /* Signature length always equal to modulus length */
  sig_len =  mbedtls_mpi_size(&ctx->N);

  /* Fill in RSA key structure using the regular public key representation */
  retval = cmox_rsa_setKey(&rsa_key, a_modulus, mbedtls_mpi_size(&ctx->N),
                           a_public_exp, mbedtls_mpi_size(&ctx->E));
  if (retval != CMOX_RSA_SUCCESS)
  {
    ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    goto exit;
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v22_verify(&ctx->rsa_ctx, &rsa_key, hash, p_hash_id,
                                    (size_t)expected_salt_len, sig, sig_len,
                                    &fault_check);
  if (retval != CMOX_RSA_AUTH_SUCCESS)
  {
    /* Problem occur return retval, fault check could be a dirty value */
    ret = rsa_mbed_return_value(retval);
  }
  else
  {
    /* retval is good, it's not means verify success,
       check the fault_check variable to conclude */
    ret = rsa_mbed_return_value(fault_check);
  }

exit:
  mbedtls_free(p_working_buffer);
  return ret;
}

/**
  * @brief Simplified PKCS#1 v2.1 RSASSA-PSS-VERIFY function
  */
int mbedtls_rsa_rsassa_pss_verify(mbedtls_rsa_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  unsigned int hashlen,
                                  const unsigned char *hash,
                                  const unsigned char *sig)
{
  mbedtls_md_type_t mgf1_hash_id;
  if (((md_alg != MBEDTLS_MD_NONE) || (hashlen != 0U)) && (hash == NULL))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  mgf1_hash_id = (ctx->hash_id != (int)MBEDTLS_MD_NONE)
                 ? (mbedtls_md_type_t) ctx->hash_id
                 : md_alg;

  return mbedtls_rsa_rsassa_pss_verify_ext(ctx,
                                           md_alg, hashlen, hash,
                                           mgf1_hash_id, MBEDTLS_RSA_SALT_LEN_ANY,
                                           sig);

}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/**
  * @brief Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-v1_5-VERIFY function
  */
int mbedtls_rsa_rsassa_pkcs1_v15_verify(mbedtls_rsa_context *ctx,
                                        mbedtls_md_type_t md_alg,
                                        unsigned int hashlen,
                                        const unsigned char *hash,
                                        const unsigned char *sig)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED; /* Final return value */
  cmox_rsa_retval_t retval = 0;                   /* STCryptoLib return value */
  cmox_rsa_pkcs1v15_hash_t p_hash_id = 0;     /* Hash id for cmox operation */
  cmox_rsa_key_t rsa_key = {0};               /* Rsa key with STCryptoLib format */
  uint8_t a_modulus[ST_MOD_MAX_SIZE / 8] = {0}; /* Modulus as array */
  uint8_t a_public_exp[PUBLIC_EXP_LEN] = {0}; /* Public exponent as array */
  uint8_t *p_working_buffer = NULL;           /* RSA working buffer */
  uint16_t buff_size = ST_BUFFER_SIZE_PKCS1_V15; /* Max space needed by STCryptoLib */
  uint32_t fault_check = CMOX_RSA_AUTH_FAIL;  /* Fault check variable */
  uint32_t sig_len = 0;                       /* Theoretical signature length */

  if (ctx->padding != MBEDTLS_RSA_PKCS_V15)
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  /* Allocate the working buffer for the STCryptoLib */
  p_working_buffer = mbedtls_calloc(buff_size, sizeof(uint8_t));
  if (p_working_buffer == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Construct the RSA context */
  cmox_rsa_construct(&ctx->rsa_ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PUBLIC,
                     p_working_buffer, buff_size);

  /* Convert mbedtls_md_type_t to cmox_rsa_pkcs1v15_hash_t for the hash id */
  p_hash_id = rsa_alt_hashId_1v15(md_alg, hashlen);

  /* Use mbedtls_mpi_size for the size and not sizeof(modulus) for avoid
     zero padding in output buffer */
  if (mbedtls_mpi_size(&ctx->N) > sizeof(a_modulus))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;

  }
  ret = mbedtls_mpi_write_binary(&ctx->N, a_modulus,
                                 mbedtls_mpi_size(&ctx->N));
  if (ret != 0)
  {
    goto exit;
  }

  /* Use mbedtls_mpi_size for the size and not sizeof(E) for avoid zero
     padding in output buffer */
  if (mbedtls_mpi_size(&ctx->E) > sizeof(a_public_exp))
  {
    ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    goto exit;
  }
  ret = mbedtls_mpi_write_binary(&ctx->E, a_public_exp,
                                 mbedtls_mpi_size(&ctx->E));
  if (ret != 0)
  {
    goto exit;
  }

  /* Signature length always equal to modulus length */
  sig_len =  mbedtls_mpi_size(&ctx->N);

  /* Fill in RSA key structure using the regular public key representation */
  retval = cmox_rsa_setKey(&rsa_key, a_modulus, mbedtls_mpi_size(&ctx->N),
                           a_public_exp, mbedtls_mpi_size(&ctx->E));
  if (retval != CMOX_RSA_SUCCESS)
  {
    ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    goto exit;
  }

  /* Compute directly the signature passing all the needed parameters */
  retval = cmox_rsa_pkcs1v15_verify(&ctx->rsa_ctx, &rsa_key, hash, p_hash_id,
                                    sig, sig_len, &fault_check);
  if (retval != CMOX_RSA_AUTH_SUCCESS)
  {
    /* Problem occur return retval value, fault check could be a dirty */
    ret = rsa_mbed_return_value(retval);
  }
  else
  {
    /* retval is good, it's not means verify success,
       check the fault_check variable to conclude */
    ret = rsa_mbed_return_value(fault_check);
  }

exit:
  mbedtls_free(p_working_buffer);
  return ret;
}
#endif /* MBEDTLS_PKCS1_V15 */

/**
  * @brief Do an RSA operation and check the message digest
  */
int mbedtls_rsa_pkcs1_verify(mbedtls_rsa_context *ctx,
                             mbedtls_md_type_t md_alg,
                             unsigned int hashlen,
                             const unsigned char *hash,
                             const unsigned char *sig)
{
  if (((md_alg != MBEDTLS_MD_NONE) || (hashlen != 0U)) && (hash == NULL))
  {
    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
  }

  switch (ctx->padding)
  {
#if defined(MBEDTLS_PKCS1_V15)
    case MBEDTLS_RSA_PKCS_V15:
      return mbedtls_rsa_rsassa_pkcs1_v15_verify(ctx, md_alg,
                                                 hashlen, hash, sig);
      break;
#endif  /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
    case MBEDTLS_RSA_PKCS_V21:
      return mbedtls_rsa_rsassa_pss_verify(ctx, md_alg,
                                           hashlen, hash, sig);
      break;
#endif  /* MBEDTLS_PKCS1_V21 */

    default:
      return MBEDTLS_ERR_RSA_INVALID_PADDING;
      break;
  }
}

/**
  * @brief Copy the components of an RSA key
  */
int mbedtls_rsa_copy(mbedtls_rsa_context *dst, const mbedtls_rsa_context *src)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

  dst->ver = src->ver;
  dst->len = src->len;

  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->N, &src->N));
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->E, &src->E));

  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->D, &src->D));
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->P, &src->P));
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->Q, &src->Q));

#if !defined(MBEDTLS_RSA_NO_CRT)
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->DP, &src->DP));
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->DQ, &src->DQ));
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->QP, &src->QP));
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->RP, &src->RP));
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->RQ, &src->RQ));
#endif /* !MBEDTLS_RSA_NO_CRT */

  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->RN, &src->RN));

  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->Vi, &src->Vi));
  MBEDTLS_MPI_CHK_RSA_ALT(mbedtls_mpi_copy(&dst->Vf, &src->Vf));

  dst->padding = src->padding;
  dst->hash_id = src->hash_id;

cleanup:
  if (ret != 0)
  {
    mbedtls_rsa_free(dst);
  }

  return ret;
}

/**
  * @brief Free the components of an RSA key
  */
void mbedtls_rsa_free(mbedtls_rsa_context *ctx)
{
  if (ctx == NULL)
  {
    return;
  }

  mbedtls_mpi_free(&ctx->Vi);
  mbedtls_mpi_free(&ctx->Vf);
  mbedtls_mpi_free(&ctx->RN);
  mbedtls_mpi_free(&ctx->D);
  mbedtls_mpi_free(&ctx->Q);
  mbedtls_mpi_free(&ctx->P);
  mbedtls_mpi_free(&ctx->E);
  mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
  mbedtls_mpi_free(&ctx->RQ);
  mbedtls_mpi_free(&ctx->RP);
  mbedtls_mpi_free(&ctx->QP);
  mbedtls_mpi_free(&ctx->DQ);
  mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */

#if defined(MBEDTLS_THREADING_C)
  mbedtls_mutex_free(&ctx->mutex);
#endif /* MBEDTLS_THREADING_C */
}

/**
  * @}
  */

#endif /* MBEDTLS_STCRYPTOLIB_RSA_ALT */

#endif /* MBEDTLS_RSA_ALT */
#endif /* MBEDTLS_RSA_C */
