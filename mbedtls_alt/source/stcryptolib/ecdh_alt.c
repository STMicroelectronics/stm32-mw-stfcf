/**
  ******************************************************************************
  * @file    ecdh_alt.c
  * @brief   Implementation of mbedtls_alt Middleware ECDH module
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
  * Elliptic curve Diffie-Hellman compute shared functions
  * This file implements Elliptic curve Diffie-Hellman compute shared
  * functions based on STM32 crypto library.
  */

/* Includes ------------------------------------------------------------------*/
#include "common.h"
#if defined(MBEDTLS_ECDH_C)
#include "mbedtls/ecdh.h"
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#define MBEDTLS_MPI_CHK_ECDH_ALT(f) \
  do                           \
  {                            \
    ret = (f);                 \
    if (ret != 0)              \
    {                          \
      goto cleanup;            \
    }                          \
  } while (0)

#if defined(MBEDTLS_STCRYPTOLIB_ECDH_ALT)
#include "cmox_crypto.h"

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define ST_BUFFER_SIZE_256 1648
#define ST_BUFFER_SIZE_384 2272
#define ST_BUFFER_SIZE_MAX 4000    /* Max space needed by STCryptoLib */
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/** @cond DOXYGEN_SHOULD_SKIP_THIS */
/* Convert return value from STCryptoLib to MBED for ecc */
static int ecc_mbed_return_value(cmox_ecc_retval_t retval)
{
  int ret = 0; /* Return value */

  switch (retval)
  {
    case CMOX_ECC_SUCCESS:
      ret = 0;
      break;

    case CMOX_ECC_ERR_INTERNAL:
      ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
      break;

    case CMOX_ECC_ERR_BAD_PARAMETERS:
      ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
      break;

    case CMOX_ECC_ERR_INVALID_PUBKEY:
      ret = MBEDTLS_ERR_ECP_INVALID_KEY;
      break;

    case CMOX_ECC_ERR_INVALID_SIGNATURE:
      ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
      break;

    case CMOX_ECC_ERR_WRONG_RANDOM:
      ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
      break;

    case CMOX_ECC_ERR_MEMORY_FAIL:
      ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
      break;

    case CMOX_ECC_ERR_MATHCURVE_MISMATCH:
      ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
      break;

    case CMOX_ECC_ERR_ALGOCURVE_MISMATCH:
      ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
      break;

    case CMOX_ECC_AUTH_SUCCESS:
      ret = (0);
      break;

    case CMOX_ECC_AUTH_FAIL:
      ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
      break;

    default :
      ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;
      break;
  }
  return ret;
}

static cmox_ecc_impl_t ecc_alt_curveId(mbedtls_ecp_group_id grp)
{
  cmox_ecc_impl_t retval = 0; /* Return value */

  /* Select correct hash id */
  switch (grp)
  {
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
    case MBEDTLS_ECP_DP_SECP224R1:
      retval = CMOX_ECC_CURVE_SECP224R1;
      break;
#endif /* MBEDTLS_ECP_DP_SECP224R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    case MBEDTLS_ECP_DP_SECP256R1:
      retval = CMOX_ECC_CURVE_SECP256R1;
      break;
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
    case MBEDTLS_ECP_DP_SECP384R1:
      retval = CMOX_ECC_CURVE_SECP384R1;
      break;
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
    case MBEDTLS_ECP_DP_SECP521R1:
      retval = CMOX_ECC_CURVE_SECP521R1;
      break;
#endif /* MBEDTLS_ECP_DP_SECP521R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
    case MBEDTLS_ECP_DP_BP256R1:
      retval = CMOX_ECC_CURVE_BPP256R1;
      break;
#endif /* MBEDTLS_ECP_DP_BP256R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
    case MBEDTLS_ECP_DP_BP384R1:
      retval = CMOX_ECC_CURVE_BPP384R1;
      break;
#endif /* MBEDTLS_ECP_DP_BP384R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
    case MBEDTLS_ECP_DP_BP512R1:
      retval = CMOX_ECC_CURVE_BPP512R1;
      break;
#endif /* MBEDTLS_ECP_DP_BP512R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
    case MBEDTLS_ECP_DP_SECP256K1:
      retval = CMOX_ECC_CURVE_SECP256K1;
      break;
#endif /* MBEDTLS_ECP_DP_SECP256K1_ENABLED */
    default :
      retval = 0;  /* Not supported by STCryptoLib */
      break;
  }
  return retval;
}


#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
static int ecdh_compute_shared_restartable(mbedtls_ecp_group *grp,
                                           mbedtls_mpi *z,
                                           const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void *p_rng,
                                           mbedtls_ecp_restart_ctx *rs_ctx)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  cmox_ecc_retval_t retval;             /* STCryptoLib return value */
  cmox_ecc_impl_t curve_id = 0;         /* Curve ID for STCryptoLib */
  uint8_t *p_working_buffer = NULL;     /* ECC working buffer for STCryptoLib */
  uint16_t buff_size = 0;               /* space needed by STCryptoLib */
  cmox_ecc_handle_t ecc_ctx;            /* Ecc ctx for STCryptoLib */
  uint8_t priv_key_size;                /* Private key size */
  size_t public_key_size;               /* Length of public key in bytes set by mbed */
  size_t order_size = 0U;
  size_t key_size = 0U;
  size_t computed_size = 0U;            /* Size of the computed secret (part X) by STCryptoLib */
  uint8_t *p_private_key = NULL;        /* Private key */
  uint8_t *p_public_key = NULL;         /* Public key X + Y */
  uint8_t *p_computed_secret = NULL;    /* Secret part X */
  cmox_init_arg_t init_arg;             /* Init structure for STCryptoLib */

  /* Select curve id */
  curve_id = ecc_alt_curveId(grp->id);

  if (curve_id == 0)
  {
    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
  }

  switch (grp->id)
  {
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    case MBEDTLS_ECP_DP_SECP256R1:
      buff_size = ST_BUFFER_SIZE_256;
      break;
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
    case MBEDTLS_ECP_DP_SECP384R1:
      buff_size = ST_BUFFER_SIZE_384;
      break;
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
    default :
      buff_size = ST_BUFFER_SIZE_MAX;
      break;
  }

  /* Allocate the working buffer for the STCryptoLib */
  p_working_buffer = mbedtls_calloc(buff_size, sizeof(uint8_t));
  if (p_working_buffer == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Init the STCryptoLib */
  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  cmox_initialize(&init_arg);

  cmox_ecc_construct(&ecc_ctx, CMOX_MATH_FUNCS_FAST, p_working_buffer, buff_size);

  order_size = mbedtls_mpi_size(&grp->N);

  /* Use mbedtls_mpi_size for the size and not sizeof(d) for avoid zero padding in output buffer. */
  priv_key_size = (uint8_t)mbedtls_mpi_size(d);

  p_private_key = mbedtls_calloc(priv_key_size, sizeof(uint8_t));
  if (p_private_key == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  MBEDTLS_MPI_CHK_ECDH_ALT(mbedtls_mpi_write_binary(d, p_private_key, priv_key_size));

  p_public_key = mbedtls_calloc(2U * order_size + 1U, sizeof(uint8_t));

  if (p_public_key == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  key_size = 2U * order_size + 1U;

  /* Convert public key to an array */
  MBEDTLS_MPI_CHK_ECDH_ALT(mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                          &public_key_size, p_public_key, key_size));
  public_key_size--; /* Remove first byte at 0x04, it's a byte for format */

  p_computed_secret = mbedtls_calloc(2U * order_size, sizeof(uint8_t));
  if (p_computed_secret == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  retval = cmox_ecdh(&ecc_ctx, curve_id, p_private_key, priv_key_size, &p_public_key[1],
                     public_key_size, p_computed_secret, &computed_size);

  if (retval != CMOX_ECC_SUCCESS)
  {
    ret = ecc_mbed_return_value(retval);
    goto cleanup;
  }
  /* Convert the secret part X into mpi format */
  ret = mbedtls_mpi_read_binary(z, &p_computed_secret[0], computed_size / 2U);

cleanup:
  mbedtls_free(p_working_buffer);
  mbedtls_free(p_computed_secret);
  mbedtls_free(p_private_key);
  mbedtls_free(p_public_key);
  return ret;

}
/** @endcond */

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
  return ecdh_compute_shared_restartable(grp, z, Q, d, f_rng, p_rng, NULL);
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */
#endif /* MBEDTLS_STCRYPTOLIB_ECDH_ALT */
#endif /* MBEDTLS_ECDH_C */
