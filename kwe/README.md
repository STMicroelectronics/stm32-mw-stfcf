# __Key Wrap Engine__

This PSA driver is a part of the STM32 Flexible Crypto Framework (STFCF) middleware provided by STMicroelectronics.

## __1. Abstract__

The Key Wrap Engine (KWE) is a software component that provides a set of APIs for performing protected cryptographic operations
on STM32 internal hardware crypto accelerators using symmetric and asymmetric wrapped keys.

This software allows applications to perform protected cryptographic operations using wrapped keys that are never disclosed to the
application in cleartext. The keys are stored by the application in wrapped form. It enables the signing of the token for initial
attestation with the device attestation keys (DUA_FU, or DUA_LU) and the export of the public key.

## __2. Description__
This component repository contains an implementation of the middleware to interface with the PSA Crypto API as an opaque driver.

* **Supported Protected Cryptographic Operations **

<center>

| Algorithms     | Key Import | Key Generate | Encryption | Decryption | Key Agreement | Signature | Pub Key Export |
| -------------- |:----------:|:------------:|:----------:|:----------:|:-------------:|:---------:|:--------------:|
| AES CBC        |    YES     |    NO        |    YES     |     YES    |     NO        |    NO     |    NO          |
| AES ECB        |    YES     |    NO        |    YES     |     YES    |     NO        |    NO     |    NO          |
| AES GCM        |    YES     |    NO        |    YES     |     YES    |     NO        |    NO     |    NO          |
| AES CCM        |    YES     |    NO        |    YES     |     YES    |     NO        |    NO     |    NO          |
| ECDH           |    YES     |    YES       |    NO      |     NO     |     YES       |    NO     |    NO          |
| ECDSA          |    YES     |    YES       |    NO      |     NO     |     NO        |    YES    |    YES         |
| RSA PKCS(v1.5) |    YES     |    NO        |    NO      |     NO     |     NO        |    YES    |    NO          |
| RSA PKCS(v2.2) |    YES     |    NO        |    NO      |     YES    |     NO        |    YES    |    NO          |

</center>

## __3. How to use it?__

 This can be achieved by :

  * Adding STM32 Flexible Crypto Framework to user application.

  * Defining the appropriate `MBEDTLS_ENTROPY_HARDWARE_ALT` preprocessor symbol in `mbedtls_config.h` to enable hardware entropy alternative.

  * Defining the appropriate preprocessor `MBEDTLS_HAL_ENTROPY_HARDWARE_ALT` in mbedtls_alt_config.h to enable STM32 hardware entropy source.

  * Defining the appropriate preprocessor `KWE_DRIVER_ENABLED` in kwe_config.h to enable STM32 Mbed TLS Key Wrap Engine core module.

  * Defining the appropriate preprocessor `PSA_KWE_DRIVER_ENABLED` in kwe_config.h to Enable STM32 Mbed TLS Key Wrap Engine interface module to PSA Crpto API.

  * Defining the appropriate preprocessor `KWE_ASYMMETRIC_KEY_WRAP_ENABLED` in kwe_config.h to Enable STM32 Mbed TLS Key Wrap Engine for asymmetric keys.

  **Use case : Generate ECDSA wrapped key for ECDSA signature and export the public key**

  * Add Middleware: Ensure the STFCF and MbedTLS middleware are included in the project.

  * Define Preprocessors: Enable the necessary preprocessor symbols in the respective configuration files.

  * Add STM32Cube HAL drivers for STM32 hardware cryptographic accelerator to the project.

  * Generate and Export Key: Follow the steps to initialize the PSA cryptographic library, generate the ECDSA key pair, wrap the private key, export the public key, and clean up resources
  * Initialize the PSA Crypto Library using `psa_crypto_init()`.
  * Generate an ECDSA Key Pair: Key attributes should set to specify the key lifetime external using STM32 Mbed TLS Key Wrap Engine location : `PSA_CRYPTO_KWE_DRIVER_LOCATION`.
  * The key is then generated in wrapped forme using `psa_generate_key()`.
  * Compute the hash of the message using `psa_hash_compute()`.
  * Sign the hash using  `psa_sign_hash()`.
  * Export the Public Key using `psa_export_public_key()`.
  * Clean up resources using `psa_destroy_key()`.
