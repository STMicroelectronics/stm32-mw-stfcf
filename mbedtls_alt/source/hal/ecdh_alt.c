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
  * functions based on STM32 PKA hardware crypto accelerator.
  */
/* Includes ------------------------------------------------------------------*/
#include "mbedtls/ecdh.h"
#include <string.h>
#define MBEDTLS_MPI_CHK_ECDH_ALT(f) \
  do                           \
  {                            \
    ret = (f);                 \
    if (ret != 0)              \
    {                          \
      goto cleanup;            \
    }                          \
  } while (0)

#if defined(MBEDTLS_ECDH_C)
#if defined(MBEDTLS_ECP_ALT)
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_HAL_ECDH_ALT)
/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define ST_ECDH_TIMEOUT     (5000U)
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/
#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/** @cond DOXYGEN_SHOULD_SKIP_THIS */
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
  (void) f_rng;
  (void) p_rng;
  (void) rs_ctx;
  hal_pka_ecc_mul_protect_config_t ECDH_input = {0};    /* ECDSA Curve struct */
  hal_pka_ecc_mul_protect_result_t ECDH_ouput = {0};    /* ECDSA point = shared secret */
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;      /* MBED return value */
  uint8_t *d_binary = NULL;                             /* Pointer to private key */
  size_t olen = 0;                                      /* Length of the point, internal use */
  uint8_t *Q_binary = NULL;                             /* Pointer to public key */
  uint32_t padding_size = 0U;
  uint32_t size_byte = 0U;
  hal_pka_handle_t *pPKA = NULL;                        /* PKA handle Pointer */
  pPKA = mx_stfcf_mbedtls_alt_hal_pka_gethandle();

  /* Set HW peripheral input parameter : private key */
  d_binary = mbedtls_calloc(grp->st_order_size, sizeof(uint8_t));
  MBEDTLS_MPI_CHK_ECDH_ALT((d_binary == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
  MBEDTLS_MPI_CHK_ECDH_ALT(mbedtls_mpi_write_binary(d, d_binary, grp->st_order_size));

  /* Set HW peripheral Input parameter */
  ECDH_input.p_scalar_mul = d_binary;

  /* Set scalar multiplier Input parameter */
  ECDH_input.modulus_size_byte     = grp->st_modulus_size;
  ECDH_input.coeff_sign            = grp->st_a_sign;
  ECDH_input.p_coeff_a             = grp->st_a_abs;
  ECDH_input.p_coeff_b             = grp->st_b;
  ECDH_input.p_modulus             = grp->st_p;
  ECDH_input.scalar_mul_size_byte  = grp->st_order_size;
  ECDH_input.p_prime_order         = grp->st_n;
  ECDH_input.prime_order_size_byte = grp->st_order_size;

  /* Set the public key, this is the remote data */
  Q_binary = mbedtls_calloc((2U * grp->st_modulus_size) + 1U, sizeof(uint8_t));
  MBEDTLS_MPI_CHK_ECDH_ALT((Q_binary == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
  MBEDTLS_MPI_CHK_ECDH_ALT(mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, Q_binary,
                                                          (2U * grp->st_modulus_size) + 1U));
  ECDH_input.p_pt_x = Q_binary + 1U;
  ECDH_input.p_pt_y = Q_binary + grp->st_modulus_size + 1U;

  /* PKA ECC configuration */
  if (HAL_PKA_ECC_SetConfigMulProtect(pPKA, &ECDH_input) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  /* Start the ECC scalar multiplication */
  if (HAL_PKA_Compute(pPKA, ST_ECDH_TIMEOUT) != HAL_OK)
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }

  /* Allocate memory space for computed secret */
  ECDH_ouput.p_pt_x = mbedtls_calloc(grp->st_order_size, sizeof(uint8_t));
  MBEDTLS_MPI_CHK_ECDH_ALT((ECDH_ouput.p_pt_x == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
  ECDH_ouput.p_pt_y = mbedtls_calloc(grp->st_order_size, sizeof(uint8_t));
  MBEDTLS_MPI_CHK_ECDH_ALT((ECDH_ouput.p_pt_y == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);

  /* Copy the results to user specified space */
  size_byte = HAL_PKA_ECC_GetResultMulProtect(pPKA, &ECDH_ouput);
  if ((size_byte == 0U) || (size_byte > grp->st_order_size))
  {
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
  }
  /* Left pad result to fixed size */
  if (size_byte < grp->st_order_size)
  {
    padding_size = grp->st_order_size - size_byte;
    (void) memmove(ECDH_ouput.p_pt_x + padding_size, ECDH_ouput.p_pt_x, size_byte);
    (void) memset(ECDH_ouput.p_pt_x, 0, padding_size);
  }

  /* Convert the signature into mpi format */
  MBEDTLS_MPI_CHK_ECDH_ALT(mbedtls_mpi_read_binary(z, ECDH_ouput.p_pt_x, grp->st_order_size));

cleanup:
  /* Free memory */
  if (d_binary != NULL)
  {
    mbedtls_platform_zeroize(d_binary, grp->st_order_size);
    mbedtls_free(d_binary);
  }
  if (Q_binary != NULL)
  {
    mbedtls_platform_zeroize(Q_binary, (2U * grp->st_modulus_size) + 1U);
    mbedtls_free(Q_binary);
  }
  if (ECDH_ouput.p_pt_x != NULL)
  {
    mbedtls_platform_zeroize(ECDH_ouput.p_pt_x, grp->st_order_size);
    mbedtls_free(ECDH_ouput.p_pt_x);
  }
  if (ECDH_ouput.p_pt_y != NULL)
  {
    mbedtls_platform_zeroize(ECDH_ouput.p_pt_y, grp->st_order_size);
    mbedtls_free(ECDH_ouput.p_pt_y);
  }
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
#endif /* MBEDTLS_HAL_ECDH_ALT */
#endif /* MBEDTLS_ECP_ALT */
#endif /* MBEDTLS_ECDH_C */
