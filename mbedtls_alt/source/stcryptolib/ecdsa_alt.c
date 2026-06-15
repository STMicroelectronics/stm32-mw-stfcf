/**
  ******************************************************************************
  * @file    ecdsa_alt.c
  * @brief   Implementation of mbedtls_alt ECDSA module
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
  * Elliptic curve DSA sign and verify functions
  *
  * This file implements ECDSA sign and verify based on STM32 crypto library.
  */

/* Includes ------------------------------------------------------------------*/
#include "common.h"

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_STCRYPTOLIB_ECDSA_ALT)
#include "cmox_crypto.h"

#if defined(MCUBOOT_DOUBLE_SIGN_VERIF)
#include "boot_hal_imagevalid.h"
#endif /* MCUBOOT_DOUBLE_SIGN_VERIF */

/* Private typedef -----------------------------------------------------------*/
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

static cmox_ecc_impl_t ecdsa_alt_curveId(mbedtls_ecp_group_id grp)
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
/** @endcond */

#if defined(MBEDTLS_ECDSA_SIGN_ALT)

/*
 * Compute ECDSA signature of a hashed message
 */
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d,
                       const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  cmox_rsa_retval_t retval;             /* STCryptoLib return value */
  cmox_ecc_impl_t curve_id = 0;         /* Curve ID for STCryptoLib */
  uint8_t *p_working_buffer = NULL;     /* ECDSA working buffer for STCryptoLib */
  uint16_t buff_size = 0;               /* space needed by STCryptoLib */
  cmox_ecc_handle_t ecc_ctx;            /* Ecc ctx for STCryptoLib */
  cmox_init_arg_t init_arg;             /* Init structure for STCryptoLib */
  uint8_t *p_private_key = NULL;
  uint8_t priv_key_size;                /* Private key size */
  uint8_t *p_computed_signature = NULL;
  size_t signature_size = 0U;           /* Size of the calculated signature by STCryptoLib */
  mbedtls_mpi k;                        /* K, the random with mbed format */
  uint8_t *p_k_binary = NULL;
  uint32_t k_size = 0;                  /* Size of K */
  uint8_t pos = 0;                      /* Internal counter for K derivation */
  int mpi_n = mbedtls_mpi_cmp_mpi(d, &grp->N);
  int mpi_0 = mbedtls_mpi_cmp_int(d, 1);
  /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
  if (!(mbedtls_ecdsa_can_do(grp->id) != 0) || (grp->N.MBEDTLS_PRIVATE(p) == NULL))
  {
    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
  }

  /* Make sure d is in range 1..n-1 */
  if ((mpi_0 < 0) || (mpi_n >= 0))
  {
    return MBEDTLS_ERR_ECP_INVALID_KEY;
  }

  /* Select curve id */
  curve_id = ecdsa_alt_curveId(grp->id);

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

  mbedtls_mpi_init(&k);

  /* Generate the random of length random_length */
  ret = mbedtls_ecp_gen_privkey(grp, &k, f_rng, p_rng);
  if (ret != 0)
  {
    goto exit;
  }

  k_size = (grp->nbits + 7U) / 8U ;

  p_k_binary = mbedtls_calloc(k_size, sizeof(uint8_t));
  if (p_k_binary == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }
  ret = mbedtls_mpi_write_binary(&k, p_k_binary, k_size);
  if (ret != 0)
  {
    goto exit;
  }

  /* StyCryptoLib use k-1 and not k */
  pos = (uint8_t)(k_size - 1U);
  p_k_binary[pos]--;
  if (p_k_binary[k_size - 1U] == 0xFFU)
  {
    do
    {
      pos--; /* Manage overflow */
      p_k_binary[pos]--;
    } while ((p_k_binary[pos] == 0xFFU) && (pos > 1U));
  }

  /* Init the STCryptoLib */
  init_arg.target = CMOX_INIT_TARGET_AUTO;
  init_arg.pArg = NULL;
  if (cmox_initialize(&init_arg) != CMOX_INIT_SUCCESS)
  {
    return -1;
  }

  cmox_ecc_construct(&ecc_ctx, CMOX_MATH_FUNCS_FAST, p_working_buffer,
                     buff_size);

  /* Use mbedtls_mpi_size for the size and not sizeof(d) for avoid zero
     padding in output buffer. */
  priv_key_size = (uint8_t)mbedtls_mpi_size(d);

  p_private_key = mbedtls_calloc(priv_key_size, sizeof(uint8_t));
  if (p_private_key == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }
  ret = mbedtls_mpi_write_binary(d, p_private_key, priv_key_size);
  if (ret != 0)
  {
    goto exit;
  }

  p_computed_signature = mbedtls_calloc(2U * mbedtls_mpi_size(&grp->N), sizeof(uint8_t));
  if (p_computed_signature == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  retval = cmox_ecdsa_sign(&ecc_ctx, curve_id, p_k_binary, k_size,
                           p_private_key, priv_key_size,
                           buf, blen, p_computed_signature, &signature_size);

  if (retval != CMOX_ECC_SUCCESS)
  {
    ret = ecc_mbed_return_value(retval);
    goto exit;
  }

  /* Convert the signature into mpi format */
  ret = mbedtls_mpi_read_binary(r, &p_computed_signature[0], signature_size / 2U);
  if (ret == 0)
  {
    ret = mbedtls_mpi_read_binary(s, &p_computed_signature[signature_size / 2U],
                                  signature_size / 2U);
  }

exit:
  mbedtls_free(p_working_buffer);
  mbedtls_free(p_private_key);
  mbedtls_free(p_k_binary);
  mbedtls_free(p_computed_signature);
  return ret;
}

#endif /* MBEDTLS_ECDSA_SIGN_ALT*/

#if defined(MBEDTLS_ECDSA_VERIFY_ALT)


/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp, const unsigned char *buf,
                         size_t blen, const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r, const mbedtls_mpi *s)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  cmox_rsa_retval_t retval;                    /* STCryptoLib return value */
  cmox_ecc_impl_t curve_id = 0;                /* Curve ID for STCryptoLib */
  uint8_t *p_working_buffer = NULL;            /* ECDSA working buffer for STCryptoLib */
  uint16_t buff_size = 0;                      /* space needed by STCryptoLib */
  size_t order_size = 0U;
  size_t signature_size = 0U;
  size_t buffer_size = 0U;
  cmox_ecc_handle_t ecc_ctx;                   /* Ecc ctx for STCryptoLib */
  cmox_init_arg_t init_arg;                    /* Init structure for STCryptoLib */
  uint32_t fault_check = CMOX_ECC_AUTH_FAIL;   /* Fault check variable */
  uint8_t *p_public_key = NULL;
  uint8_t *p_known_signature = NULL;
  size_t public_key_size = 0U;                 /* Length of public key in bytes set by mbed */
  int mpi_int = mbedtls_mpi_cmp_int(r, 1);
  int mpi_r = mbedtls_mpi_cmp_mpi(r, &grp->N);
  int mpi_s = mbedtls_mpi_cmp_int(s, 1);
  int mpi_n = mbedtls_mpi_cmp_mpi(s, &grp->N);
  /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
  if (grp->G.MBEDTLS_PRIVATE(Y).MBEDTLS_PRIVATE(p) == NULL)
  {
    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
  }

  /* Make sure r and s are in range 1..n-1 */
  if ((mpi_int < 0)
      || (mpi_r >= 0)
      || (mpi_s < 0)
      || (mpi_n >= 0))
  {
    return MBEDTLS_ERR_ECP_VERIFY_FAILED;
  }

  /* Select curve id */
  curve_id = ecdsa_alt_curveId(grp->id);

  if (curve_id == 0)
  {
    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
  }
  order_size = mbedtls_mpi_size(&grp->N);

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
  if (cmox_initialize(&init_arg) != CMOX_INIT_SUCCESS)
  {
    return -1;
  }

  cmox_ecc_construct(&ecc_ctx, CMOX_MATH_FUNCS_FAST, p_working_buffer,
                     buff_size);

  p_public_key = mbedtls_calloc((2U * order_size) + 1U, sizeof(uint8_t));
  if (p_public_key == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }
  buffer_size = (2U * order_size) + 1U;
  /* Convert public key to an array */
  ret = mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &public_key_size, p_public_key,
                                       buffer_size);
  if (ret != 0)
  {
    goto cleanup;
  }

  p_known_signature = mbedtls_calloc(2U * order_size, sizeof(uint8_t));
  if (p_known_signature == NULL)
  {
    return MBEDTLS_ERR_MPI_ALLOC_FAILED;
  }

  /* Convert signature R+S from mpi to array of bytes */
  ret = mbedtls_mpi_write_binary(r, &p_known_signature[0], order_size);
  ret |= mbedtls_mpi_write_binary(s, &p_known_signature[order_size], order_size);
  if (ret != 0)
  {
    goto cleanup;
  }

  signature_size = 2U * order_size;

  public_key_size--; /* Remove first byte at 0x04, it's a byte for format */

  retval = cmox_ecdsa_verify(&ecc_ctx, curve_id, &p_public_key[1],
                             public_key_size, buf, blen, p_known_signature,
                             signature_size, &fault_check);


  if (retval != CMOX_ECC_AUTH_SUCCESS)
  {
    /* Problem occur return retval value,
       fault check could be a dirty value */
    ret = ecc_mbed_return_value(retval);
  }
  else
  {
    /* retval is good, it's not means verify success,
       check the fault check to conclude */
    ret = ecc_mbed_return_value(fault_check);

#if defined(MCUBOOT_DOUBLE_SIGN_VERIF)
    /* Double the signature verification (using another way) to resist to basic HW attacks.
     * The second verification is applicable to final signature check on primary slot images
     * only (condition: ImageValidEnable).
     * It is performed in 2 steps:
     * 1- save signature status in global variable ImageValidStatus[]
     *    Return value of comparison function is XORed with IMAGE_VALID to avoid
     *    value 0 for success: IMAGE_VALID for success.
     * 2- verify saved signature status later in boot process
     */
    if (ImageValidEnable == 1)
    {
      /* Check ImageValidIndex is in expected range MCUBOOT_IMAGE_NUMBER */
      if (ImageValidIndex >= MCUBOOT_IMAGE_NUMBER)
      {
        ret = ecc_mbed_return_value(CMOX_ECC_AUTH_FAIL);
        goto cleanup;
      }
      ImageValidStatus[ImageValidIndex++] = ret ^ IMAGE_VALID;
    }
#endif /* MCUBOOT_DOUBLE_SIGN_VERIF */
  }


cleanup:
  mbedtls_free(p_working_buffer);
  mbedtls_free(p_public_key);
  mbedtls_free(p_known_signature);
  return ret;
}

#endif /* MBEDTLS_ECDSA_VERIFY_ALT*/
#endif /* MBEDTLS_STCRYPTOLIB_ECDSA_ALT */
#endif /* MBEDTLS_ECDSA_C */
