# origin-pack: STMicroelectronics::stfcf@2.1.0
# file-format: 1.0.0
project(STMicroelectronics_stfcf_2_1_0)
cmake_minimum_required(VERSION 3.20)
add_library(STMicroelectronics_stfcf_2_1_0 INTERFACE)

# List of all CMSIS properties that influence conditions for this package
if(NOT DEFINED CMSIS_Dname)
  set(CMSIS_Dname "CMSIS_Dname not set")
  message(DEBUG "CMSIS_Dname is not set to any value")
endif()

if(NOT DEFINED CMSIS_Dvendor)
  set(CMSIS_Dvendor "CMSIS_Dvendor not set")
  message(DEBUG "CMSIS_Dvendor is not set to any value")
endif()


# Device specific defined symbols




# Include Pre_Include_Global.h globally if needed
if(CMSIS_Tcompiler STREQUAL "IAR")
    target_compile_options(STMicroelectronics_stfcf_2_1_0 INTERFACE "SHELL:--preinclude $<QUOTE>${CMAKE_CURRENT_LIST_DIR}/Pre_Include_Global.h$<QUOTE>")
else()
    target_compile_options(STMicroelectronics_stfcf_2_1_0 INTERFACE "SHELL:-include $<QUOTE>${CMAKE_CURRENT_LIST_DIR}/Pre_Include_Global.h$<QUOTE>")
endif()



# Enable all components in this package
if(CMSIS_ENTIRE_STMicroelectronics_stfcf_2_1_0)
  list(APPEND CMSIS_COMPONENTS_LIST "Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:PSA API#Cversion:1.0.0")
  list(APPEND CMSIS_COMPONENTS_LIST "Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:Core#Cversion:1.0.0")
  list(APPEND CMSIS_COMPONENTS_LIST "Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:MbedTLS Alt Common#Cversion:1.0.0")
  list(APPEND CMSIS_COMPONENTS_LIST "Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:MbedTLS Alt STCryptoLib#Cversion:1.0.0")
  list(APPEND CMSIS_COMPONENTS_LIST "Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:MbedTLS Alt HAL#Cversion:1.0.1")
  list(APPEND CMSIS_COMPONENTS_LIST "Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:KWE#Cversion:1.0.0")
endif()

# All conditions used by this package

# condition: STMicroelectronics.stfcf.2.1.0
# description: 
if((CMSIS_Dname MATCHES "STM32.*" AND CMSIS_Dvendor STREQUAL "STMicroelectronics:13"))
  set(STMicroelectronics.stfcf.2.1.0 "1")
  message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0 enabled")
else()
  set(STMicroelectronics.stfcf.2.1.0 0)
endif()


# condition: STMicroelectronics.stfcf.2.1.0:KWE condition
# description: Requires CCB HAL driver component
set(STMicroelectronics.stfcf.2.1.0_KWE_condition "$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Device#.*Cgroup:STM32 HAL#.*Csub:CCB(#.*|$)>,>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_KWE_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:Mbed TLS Alt HAL condition
# description: Requires HAL driver component(s)
set(STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition "$<AND:$<OR:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Device#.*Cgroup:STM32 HAL#.*Csub:RNG(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Device#.*Cgroup:STM32 HAL#.*Csub:AES(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Device#.*Cgroup:STM32 HAL#.*Csub:CRYP(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Device#.*Cgroup:STM32 HAL#.*Csub:HASH(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Device#.*Cgroup:STM32 HAL#.*Csub:PKA(#.*|$)>,>>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt Common(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:Mbed TLS Alt STCryptoLib condition
# description: Requires STCryptoLib component
set(STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition "$<AND:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt Common(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STCryptoLib#.*Csub:CMOX API(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:No STFCF generator
# description: STFCF without config
set(STMicroelectronics.stfcf.2.1.0_No_STFCF_generator "$<NOT:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STM32CubeMX2 Config#.*Csub:STFCF(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_No_STFCF_generator enabled")


# condition: STMicroelectronics.stfcf.2.1.0:PSA interface conditions
# description: Ensure PSA API are satisfied
set(STMicroelectronics.stfcf.2.1.0_PSA_interface_conditions "$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:MbedTLS#.*Csub:PSA API(#.*|$)>,>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_PSA_interface_conditions enabled")


# condition: STMicroelectronics.stfcf.2.1.0:STFCF config condition
# description: STFCF possible implementations
set(STMicroelectronics.stfcf.2.1.0_STFCF_config_condition "$<AND:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:PSA API(#.*|$)>,>>,$<NOT:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:Core(#.*|$)>,>>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_STFCF_config_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt aes condition
# description: Enable aes_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_aes_condition "$<OR:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt HAL(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_aes_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt ccm condition
# description: Enable ccm_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_ccm_condition "$<OR:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt HAL(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_ccm_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt chachapoly condition
# description: Enable chachapoly_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_chachapoly_condition "$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_chachapoly_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt cmac condition
# description: Enable cmac_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_cmac_condition "$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_cmac_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt drbg condition
# description: Enable drbg_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_drbg_condition "$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_drbg_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt ecp condition
# description: Enable ecp_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_ecp_condition "$<OR:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt HAL(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_ecp_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt entropy_hw condition
# description: Enable entropy_hw_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_entropy_hw_condition "$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt HAL(#.*|$)>,>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_entropy_hw_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt gcm condition
# description: Enable aes_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_gcm_condition "$<OR:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt HAL(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_gcm_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt rsa condition
# description: Enable rsa_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_rsa_condition "$<OR:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt HAL(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_rsa_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt sha1 condition
# description: Enable sha1_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_sha1_condition "$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt HAL(#.*|$)>,>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_sha1_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt sha256 condition
# description: Enable sha256_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_sha256_condition "$<OR:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt HAL(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_sha256_condition enabled")


# condition: STMicroelectronics.stfcf.2.1.0:alt sha512 condition
# description: Enable sha512_alt implementation
set(STMicroelectronics.stfcf.2.1.0_alt_sha512_condition "$<OR:$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt STCryptoLib(#.*|$)>,>>,$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:STFCF#.*Csub:MbedTLS Alt HAL(#.*|$)>,>>>")
message(DEBUG "CMSIS condition STMicroelectronics.stfcf.2.1.0_alt_sha512_condition enabled")

# Files and components in this package
if("Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:PSA API#Cversion:1.0.0" IN_LIST CMSIS_COMPONENTS_LIST)  # High level Interface, Platform Security Architecture, as entry point; Link directly the PSA API of Mbed TLS
  message(DEBUG "Using component Security_STFCF_PSA_API_1_0_0")
  target_compile_definitions(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_PSA_interface_conditions}:-DCMSIS_USE_Security_STFCF_PSA_API_1_0_0=1>")
endif()

if("Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:Core#Cversion:1.0.0" IN_LIST CMSIS_COMPONENTS_LIST)  # Templates 
  message(DEBUG "Using component Security_STFCF_Core_1_0_0")
  target_compile_definitions(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_No_STFCF_generator}:-DCMSIS_USE_Security_STFCF_Core_1_0_0=1>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_No_STFCF_generator}:${CMAKE_CURRENT_LIST_DIR}/templates>")
endif()

if("Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:MbedTLS Alt Common#Cversion:1.0.0" IN_LIST CMSIS_COMPONENTS_LIST)  # Router for the Mbed TLS and STMicroelectronics' alternatives according to the configuration choices
  message(DEBUG "Using component Security_STFCF_MbedTLS_Alt_Common_1_0_0")
  target_compile_definitions(STMicroelectronics_stfcf_2_1_0 INTERFACE "-DCMSIS_USE_Security_STFCF_MbedTLS_Alt_Common_1_0_0=1")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common/")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_aes_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_ccm_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_chachapoly_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_cmac_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_drbg_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_ecp_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_entropy_hw_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_gcm_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_rsa_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_sha1_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_sha256_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_alt_sha512_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/common>")
endif()

if("Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:MbedTLS Alt STCryptoLib#Cversion:1.0.0" IN_LIST CMSIS_COMPONENTS_LIST)  # Mbed TLS alternative implementation thanks STM32 Cryptographic library (STCryptoLib)
  message(DEBUG "Using component Security_STFCF_MbedTLS_Alt_STCryptoLib_1_0_0")
  target_compile_definitions(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:-DCMSIS_USE_Security_STFCF_MbedTLS_Alt_STCryptoLib_1_0_0=1>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/stcryptolib>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/aes_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/ccm_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/chachapoly_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/cmac_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/drbg_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/ecdh_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/ecdsa_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/gcm_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/rsa_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/sha256_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_STCryptoLib_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/stcryptolib/sha512_alt.c>")
endif()

if("Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:MbedTLS Alt HAL#Cversion:1.0.1" IN_LIST CMSIS_COMPONENTS_LIST)  # Mbed TLS alternative implementation thanks hardware acceleration (HAL API)
  message(DEBUG "Using component Security_STFCF_MbedTLS_Alt_HAL_1_0_1")
  target_compile_definitions(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:-DCMSIS_USE_Security_STFCF_MbedTLS_Alt_HAL_1_0_1=1>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/include/hal>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/aes_aes_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/aes_ccm_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/aes_gcm_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/cryp_aes_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/cryp_ccm_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/cryp_gcm_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/ecdh_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/ecdsa_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/ecp_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/ecp_curves_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/entropy_hardware_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/rsa_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/sha1_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/sha256_alt.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_Mbed_TLS_Alt_HAL_condition}:${CMAKE_CURRENT_LIST_DIR}/mbedtls_alt/source/hal/sha512_alt.c>")
endif()

if("Cvendor:STMicroelectronics#Cclass:Security#Cgroup:STFCF#Csub:KWE#Cversion:1.0.0" IN_LIST CMSIS_COMPONENTS_LIST)  # Key Wrapping Engine
  message(DEBUG "Using component Security_STFCF_KWE_1_0_0")
  target_compile_definitions(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_KWE_condition}:-DCMSIS_USE_Security_STFCF_KWE_1_0_0=1>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_KWE_condition}:${CMAKE_CURRENT_LIST_DIR}/kwe/core>")
  target_include_directories(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_KWE_condition}:${CMAKE_CURRENT_LIST_DIR}/kwe/interface>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_KWE_condition}:${CMAKE_CURRENT_LIST_DIR}/kwe/README.md>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_KWE_condition}:${CMAKE_CURRENT_LIST_DIR}/kwe/core/kwe_core.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_KWE_condition}:${CMAKE_CURRENT_LIST_DIR}/kwe/interface/kwe_psa_driver_interface.c>")
  target_sources(STMicroelectronics_stfcf_2_1_0 INTERFACE "$<${STMicroelectronics.stfcf.2.1.0_KWE_condition}:${CMAKE_CURRENT_LIST_DIR}/kwe/interface/kwe_psa_driver_key_management.c>")
endif()

