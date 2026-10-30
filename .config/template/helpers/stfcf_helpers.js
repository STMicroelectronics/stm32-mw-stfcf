/**
  ******************************************************************************
  * @file           : stfcf_helpers.js
  * @brief          : Common Helpers functions to provide service to the STFCF
  *                   components.
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
  * ******************************************************************************
  */

/**
 * Converts a string to lowercase and replaces '-' with '_'
 * @param {string} str
 * @returns {string} formatted string
 */
function addConfigLC(str) {
  return typeof str === "string" ? str.toLowerCase().replace(/-/g, "_") : "";
}

/**
 * Safe wrapper around common function-name generation logic with error handling and logging.
 * @param {string} pppi
 * @param {string} layer
 * @param {number} index
 * @param {string} pppi_fct
 * @param {string} from_where
 * @returns {string|object} generated function name or empty object on error
 */
function helper_stfcf_get_generated_function_name(pppi, layer, index, pppi_fct, from_where) {
  try {
    console.info(`helper_stfcf_get_generated_function_name (${pppi}, ${layer}, ${index}, ${pppi_fct}), from ${from_where}`);
    return common_stfcf_get_generated_function_name(pppi, layer, index, pppi_fct);
  } catch (e) {
    console.error(`helper_stfcf_get_generated_function_name: ${e}`);
    return {};
  }
}

/**
 * Helper to generate function name string
 * @param {string} pppi
 * @param {string} layer
 * @param {number} index
 * @param {string} pppi_fct
 * @returns {string} generated function name
 */
function common_stfcf_get_generated_function_name(pppi, layer, index, pppi_fct) {
  if (typeof pppi !== "string" || typeof layer !== "string") return "";

  const index_str = index === undefined ? "" : `cfg${index + 1}`;
  return `mx_${pppi.toLowerCase()}${addConfigLC(index_str)}_${layer.toLowerCase()}${addConfigLC(pppi_fct)}`;
}

/**
 * Compute effective list by applying exclusions and inclusions on a full list
 * @param {string[]} fullList
 * @param {string[]} inputList
 * @returns {string[]}
 */
function computeEffectiveList(fullList, inputList = []) {
  if (!Array.isArray(inputList) || inputList.length === 0) return fullList;

  const excluded = inputList.filter(i => i.startsWith('!')).map(i => i.slice(1));
  const included = inputList.filter(i => !i.startsWith('!'));

  if (excluded.length > 0) return fullList.filter(i => !excluded.includes(i));
  if (included.length > 0) return included;

  return fullList;
}

/**
 * Return the effective "core.basic" view of the STFCF config.
 * Supports both legacy direct-basic shape and newer parameters shape.
 * @param {object} config
 * @returns {object}
 */
function getBasicConfig(config) {
  if (config?.core?.basic) {
    return config.core.basic;
  }

  return config || {};
}

/**
 * Evaluates cipher-related conditions based on selected algorithms and implementations.
 * @param {object} config - The configuration object, expected to have cryptography.cipher
 * @param {string[]} algorithms - List of algorithms (can include exclusions with '!' prefix)
 * @param {string[]} implementations - List of implementations (can include exclusions with '!' prefix)
 * @returns {boolean}
 */
function helper_stfcf_cipher_cdt(config, algorithms = [], implementations = []) {
  const fullImplementations = ['mbedtls', 'alt_hal', 'alt_stcryptolib', 'kwe'];
  const fullAlgorithms = ['cbc', 'ccm', 'chachapoly', 'ctr', 'ecb', 'gcm'];

  const effectiveImpls = computeEffectiveList(fullImplementations, implementations);
  const effectiveAlgos = computeEffectiveList(fullAlgorithms, algorithms);

  const basicCfg = getBasicConfig(config);
  const cipherCfg = basicCfg?.cryptography?.cipher || {};
  const implCfg = basicCfg?.implementations || {};

  for (const algo of effectiveAlgos) {
    if (!cipherCfg?.[algo]) {
      continue;
    }

    let impl;

    if (algo === 'ccm') {
      impl = implCfg?.ccm_impl;
    } else if (algo === 'gcm') {
      impl = implCfg?.gcm_impl;
    } else if (algo === 'chachapoly') {
      impl = implCfg?.chachapoly_impl;
    } else if (algo === 'cbc' || algo === 'ctr' || algo === 'ecb') {
      impl = implCfg?.aes_impl;
    }

    if (!impl) {
      impl = 'alt_hal';
      console.debug(`helper_stfcf_cipher_cdt: algo=${algo}, implementation key missing. Defaulting to impl=${impl}`);
    }

    console.debug(`helper_stfcf_cipher_cdt: algo=${algo}, impl=${impl}`);

    if (impl && effectiveImpls.includes(impl)) {
      console.info("helper_stfcf_cipher_cdt: Matching algorithm and implementation found. Returning true.");
      return true;
    }
  }

  console.info("helper_stfcf_cipher_cdt: No matching algorithm/implementation pair found. Returning false.");
  return false;
}

/**
 * Evaluate asymmetric encryption RSA condition at runtime based on selected algorithms and implementations.
 * @param {object} config - The configuration object, expected to have cryptography.asymmetric_encryption
 * @param {string[]} rsaModes - List of RSA modes (can include exclusions)
 * @param {string[]} implementations - List of implementations (can include exclusions)
 * @returns {boolean}
 */
function helper_stfcf_asym_encr_rsa_cdt(config, rsaModes = [], implementations = []) {
  const fullImplementations = ['mbedtls', 'alt_hal', 'alt_stcryptolib', 'kwe'];
  const defaultImpl = fullImplementations.includes('alt_hal') ? 'alt_hal' :
    (fullImplementations.includes('alt_stcryptolib') ? 'alt_stcryptolib' : undefined);
  const fullRsaModes = ['crt', 'no_crt'];

  const effectiveImpls = computeEffectiveList(fullImplementations, implementations);
  const effectiveRsaModes = computeEffectiveList(fullRsaModes, rsaModes);

  const basicCfg = getBasicConfig(config);
  const asymEncrCfg = basicCfg?.cryptography?.asymmetric_encryption || {};
  const implCfg = basicCfg?.implementations || {};
  const rsaMode = asymEncrCfg?.rsa_pkcs_1v2_2;
  let impl = implCfg?.rsa_impl;

  if (!impl && defaultImpl) {
    impl = defaultImpl;
    console.debug(`helper_stfcf_asym_encr_rsa_cdt: implementation key missing. Defaulting to impl=${impl}`);
  }

  if (!impl || !effectiveImpls.includes(impl)) {
    console.info("helper_stfcf_asym_encr_rsa_cdt: Implementation not in effective implementations. Returning false.");
    return false;
  }

  if (!rsaMode || !effectiveRsaModes.includes(rsaMode)) {
    console.info("helper_stfcf_asym_encr_rsa_cdt: RSA mode not in effective rsaModes. Returning false.");
    return false;
  }

  console.info("helper_stfcf_asym_encr_rsa_cdt: Condition met. Returning true.");
  return true;
}

/**
 * Evaluate key agreement condition at runtime based on selected algorithms and implementations.
 * @param {object} config - The configuration object, expected to have cryptography.key_agreement
 * @param {string[]} algorithms - List of algorithms (can include exclusions)
 * @param {string[]} implementations - List of implementations (can include exclusions)
 * @returns {boolean}
 */
function helper_stfcf_key_agre_cdt(config, algorithms = [], implementations = []) {
  const fullImplementations = ['mbedtls', 'alt_hal', 'alt_stcryptolib', 'kwe'];
  const defaultImpl = fullImplementations.includes('alt_hal') ? 'alt_hal' :
    (fullImplementations.includes('alt_stcryptolib') ? 'alt_stcryptolib' : undefined);
  const fullAlgorithms = ['ecdh'];

  const effectiveImpls = computeEffectiveList(fullImplementations, implementations);
  const effectiveAlgos = computeEffectiveList(fullAlgorithms, algorithms);

  const basicCfg = getBasicConfig(config);
  const keyAgreCfg = basicCfg?.cryptography?.key_agreement || {};
  const implCfg = basicCfg?.implementations || {};
  let impl = implCfg?.ecdh_impl;

  if (!impl && defaultImpl) {
    impl = defaultImpl;
    console.debug(`helper_stfcf_key_agre_cdt: implementation key missing. Defaulting to impl=${impl}`);
  }

  console.debug("helper_stfcf_key_agre_cdt: Current implementation in config:", impl);

  if (!impl || !effectiveImpls.includes(impl)) {
    console.info("helper_stfcf_key_agre_cdt: Implementation not in effective implementations. Returning false.");
    return false;
  }

  const algoMatch = effectiveAlgos.some(algo => {
    console.debug("helper_stfcf_key_agre_cdt: Checking algorithm in config:", algo);
    return Boolean(keyAgreCfg?.[algo]);
  });

  console.info("helper_stfcf_key_agre_cdt: Algorithm match result:", algoMatch);
  return algoMatch;
}

/**
 * Evaluate asymmetric signature condition at runtime based on selected algorithms and implementations.
 * @param {object} config - The configuration object, expected to have cryptography.asymmetric_signature
 * @param {string[]} algorithms - List of algorithms (can include exclusions)
 * @param {string[]} implementations - List of implementations (can include exclusions)
 * @returns {boolean}
 */
function helper_stfcf_asym_sign_cdt(config, algorithms = [], implementations = []) {
  const fullImplementations = ['mbedtls', 'alt_hal', 'alt_stcryptolib', 'kwe'];
  const defaultImpl = fullImplementations.includes('alt_hal') ? 'alt_hal' :
    (fullImplementations.includes('alt_stcryptolib') ? 'alt_stcryptolib' : undefined);
  const fullAlgorithms = [
    'rsa_sign_verify_1_5.crt',
    'rsa_sign_verify_1_5.no_crt',
    'rsa_sign_verify_2_2.crt',
    'rsa_sign_verify_2_2.no_crt',
    'ecdsa_sign_verify'
  ];

  /* Expand shorthand algorithms to full variants */
  const expandedAlgorithms = [];

  algorithms.forEach(algo => {
    if (algo === 'rsa_sign_verify_1_5') {
      expandedAlgorithms.push('rsa_sign_verify_1_5.crt', 'rsa_sign_verify_1_5.no_crt');
    } else if (algo === 'rsa_sign_verify_2_2') {
      expandedAlgorithms.push('rsa_sign_verify_2_2.crt', 'rsa_sign_verify_2_2.no_crt');
    } else {
      expandedAlgorithms.push(algo);
    }
  });

  const effectiveImpls = computeEffectiveList(fullImplementations, implementations);
  const effectiveAlgos = computeEffectiveList(fullAlgorithms, expandedAlgorithms);

  const basicCfg = getBasicConfig(config);
  const asymSignCfg = basicCfg?.cryptography?.asymmetric_signature || {};
  const implCfg = basicCfg?.implementations || {};

  for (const algo of effectiveAlgos) {
    console.debug(`helper_stfcf_asym_sign_cdt: Checking algorithm '${algo}'`);
    let impl;

    if (algo === 'ecdsa_sign_verify') {
      impl = implCfg?.ecdsa_impl;
    } else {
      impl = implCfg?.rsa_impl;
    }

    if (!impl && defaultImpl) {
      impl = defaultImpl;
      console.debug(`helper_stfcf_asym_sign_cdt: implementation key missing. Defaulting to impl=${impl}`);
    }

    if (!impl || !effectiveImpls.includes(impl)) {
      console.debug(`helper_stfcf_asym_sign_cdt: Implementation '${impl}' for '${algo}' is not allowed, skipping.`);
      continue;
    }

    if (algo === 'ecdsa_sign_verify') {
      if (asymSignCfg?.ecdsa_sign_verify) {
        console.info(`helper_stfcf_asym_sign_cdt: Algorithm '${algo}' matched with truthy config value. Returning true.`);
        return true;
      }
    } else {
      /* Split base and variant by dot */
      const parts = algo.split('.');
      if (parts.length !== 2) {
        console.debug(`helper_stfcf_asym_sign_cdt: Algorithm '${algo}' does not have expected dot notation, skipping.`);
        continue;
      }

      const base = parts[0];    /* e.g. 'rsa_sign_verify_1_5' */
      const variant = parts[1]; /* 'crt' or 'no_crt' */

      const configValue = asymSignCfg?.[base];
      console.debug(`helper_stfcf_asym_sign_cdt: Config value for '${base}':`, configValue);

      if (configValue && configValue.toLowerCase() === variant.toLowerCase()) {
        console.info(`helper_stfcf_asym_sign_cdt: Algorithm '${algo}' matched with variant '${configValue}'. Returning true.`);
        return true;
      }
    }
  }

  console.info("helper_stfcf_asym_sign_cdt: No matching algorithms found. Returning false.");
  return false;
}


/**
 * Evaluate message authentication code condition at runtime based on selected algorithms and implementations.
 * @param {object} config - The configuration object, expected to have cryptography.message_authentication_code
 * @param {string[]} algorithms - List of algorithms (can include exclusions)
 * @param {string[]} implementations - List of implementations (can include exclusions)
 * @returns {boolean}
 */
function helper_stfcf_mess_auth_cdt(config, algorithms = [], implementations = []) {
  const fullImplementations = ['mbedtls', 'alt_hal', 'alt_stcryptolib'];
  const defaultImpl = fullImplementations.includes('alt_hal') ? 'alt_hal' :
    (fullImplementations.includes('alt_stcryptolib') ? 'alt_stcryptolib' : undefined);
  const fullAlgorithms = ['hmac', 'cmac'];

  const effectiveImpls = computeEffectiveList(fullImplementations, implementations);
  const effectiveAlgos = computeEffectiveList(fullAlgorithms, algorithms);

  const basicCfg = getBasicConfig(config);
  const messAuthCfg = basicCfg?.cryptography?.message_authentication_code || {};
  const implCfg = basicCfg?.implementations || {};

  for (const algo of effectiveAlgos) {
    console.debug("helper_stfcf_mess_auth_cdt: Checking algorithm in config:", algo);
    if (!messAuthCfg?.[algo]) {
      continue;
    }

    let impl;
    if (algo === 'hmac') {
      impl = implCfg?.hmac_impl;
    } else if (algo === 'cmac') {
      impl = implCfg?.cmac_impl;
    }

    if (!impl && defaultImpl) {
      impl = defaultImpl;
      console.debug(`helper_stfcf_mess_auth_cdt: algo=${algo}, implementation key missing. Defaulting to impl=${impl}`);
    }

    console.debug(`helper_stfcf_mess_auth_cdt: algo=${algo}, impl=${impl}`);
    if (impl && effectiveImpls.includes(impl)) {
      console.info("helper_stfcf_mess_auth_cdt: Matching algorithm and implementation found. Returning true.");
      return true;
    }
  }

  console.info("helper_stfcf_mess_auth_cdt: No matching algorithm/implementation pair found. Returning false.");
  return false;
}

/**
 * Evaluate hash condition at runtime based on selected algorithms and implementations.
 * @param {object} config - The configuration object, expected to have cryptography.hash
 * @param {string[]} algorithms - List of algorithms (can include exclusions)
 * @param {string[]} implementations - List of implementations (can include exclusions)
 * @returns {boolean}
 */
function helper_stfcf_hash_cdt(config, algorithms = [], implementations = []) {
  const fullImplementations = ['mbedtls', 'alt_hal', 'alt_stcryptolib'];
  const fullAlgorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'];

  const effectiveImpls = computeEffectiveList(fullImplementations, implementations);
  const effectiveAlgos = computeEffectiveList(fullAlgorithms, algorithms);

  const basicCfg = getBasicConfig(config);

  const hashCfg =
    basicCfg?.cryptography?.hash ||
    {};

  const implCfg =
    basicCfg?.implementations ||
    {};

  /* Explicit "no selection" handling */
  const noAlgoSelected = effectiveAlgos.length === 0;
  const noImplSelected = effectiveImpls.length === 0;

  if (noAlgoSelected || noImplSelected) {
    console.info(`helper_stfcf_hash_cdt: no selection (algorithms=${effectiveAlgos.length}, implementations=${effectiveImpls.length}). Returning false.`);
    return false;
  }

  for (const algo of effectiveAlgos) {
    console.debug(`helper_stfcf_hash_cdt: checking algorithm='${algo}'`);

    if (!hashCfg?.[algo]) {
      console.debug(`helper_stfcf_hash_cdt: algorithm '${algo}' disabled in config, skipping.`);
      continue;
    }

    let impl;

    if (algo === 'md5') {
      impl = implCfg?.md5_impl;
    } else if (algo === 'sha1') {
      impl = implCfg?.sha1_impl;
    } else if (algo === 'sha224' || algo === 'sha256') {
      impl = implCfg?.sha256_impl;
    } else if (algo === 'sha384' || algo === 'sha512') {
      impl = implCfg?.sha512_impl;
    }

    if (!impl) {
      impl = 'alt_hal';
      console.debug(`helper_stfcf_hash_cdt: algorithm='${algo}', implementation key missing. Defaulting to implementation='${impl}'.`);
    }

    console.debug(`helper_stfcf_hash_cdt: algorithm='${algo}', implementation='${impl}'`);

    if (impl && effectiveImpls.includes(impl)) {
      console.info(`helper_stfcf_hash_cdt: match found for algorithm='${algo}' with implementation='${impl}'. Returning true.`);
      return true;
    }
  }

  console.info('helper_stfcf_hash_cdt: no matching algorithm/implementation pair found. Returning false.');
  return false;
}

/**
 * Evaluate random condition at runtime based on selected algorithms and implementations.
 * @param {object} config - The configuration object, expected to have random configuration
 * @param {string[]} algorithms - List of algorithms (can include exclusions)
 * @param {string[]} implementations - List of implementations (can include exclusions)
 * @returns {boolean}
 */
function helper_stfcf_random_cdt(config, algorithms = [], implementations = []) {
  const fullImplementations = ['mbedtls', 'alt_stcryptolib'];
  const fullAlgorithms = ['hmac', 'ctr'];

  const effectiveImpls = computeEffectiveList(fullImplementations, implementations);
  const effectiveAlgos = computeEffectiveList(fullAlgorithms, algorithms);

  const basicCfg = getBasicConfig(config);
  const randomCfg = basicCfg?.random || {};
  const implCfg = basicCfg?.implementations || {};
  let impl = implCfg?.drbg_impl;
  if (!impl) {
    impl = 'alt_stcryptolib';
    console.debug(`helper_stfcf_random_cdt: DRBG implementation is missing. Defaulting to impl='${impl}'.`);
  }
  if (!effectiveImpls.includes(impl)) {
    console.info(`helper_stfcf_random_cdt: DRBG implementation '${impl}' is not in effective implementations [${effectiveImpls.join(', ')}]. Returning false.`);
    return false;
  }

  const drbg = randomCfg?.drbg;
  if (!drbg) {
    console.info("helper_stfcf_random_cdt: DRBG algorithm is missing. Returning false.");
    return false;
  }

  const match = effectiveAlgos.includes(drbg);
  console.info(`helper_stfcf_random_cdt: drbg='${drbg}', impl='${impl}', effectiveAlgos=[${effectiveAlgos.join(', ')}], match=${match}`);
  return match;
}

/**
 * Returns the corresponding #define or commented define string for a given MbedTLS flag.
 * @param {object} config - The configuration object
 * @param {string} flag - The MbedTLS configuration flag to evaluate
 * @returns {string} The MbedTLS preprocessor directive (#define or commented out)
 */
function helper_stfcf_mbedtlsconfig_switch ( config, flag )  {
  /* Normalize both legacy basic and newer parameters paths to core.basic. */
  const basicCfg = getBasicConfig(config);

  config = config || {};
  config.core = config.core || {};
  config.core.basic = config.core.basic || basicCfg;

  /* Defensive init for direct nested accesses in a few switch cases. */
  config.core.basic.cryptography = config.core.basic.cryptography || {};
  config.core.basic.cryptography.cipher = config.core.basic.cryptography.cipher || {};
  config.core.basic.random = config.core.basic.random || {};
  config.core.basic.implementations = config.core.basic.implementations || {};

  const fcf_get = () => true;

  let result = "";
  switch(flag) {
    case "MBEDTLS_AESCE_C":
      if (helper_stfcf_cipher_cdt(config, [], []) || helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal', 'kwe']) || helper_stfcf_key_agre_cdt(config, [], ['alt_hal', 'kwe']) || helper_stfcf_asym_sign_cdt(config, [], ['alt_hal', 'kwe']) || helper_stfcf_mess_auth_cdt(config, ['cmac'], ['mbedtls', 'alt_stcryptolib']) || helper_stfcf_hash_cdt(config, [], ['alt_hal', 'kwe']) || helper_stfcf_random_cdt(config, [], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_AESCE_C";
      } else {
        result = "/* #define MBEDTLS_AESCE_C */";
      }
      break;
    case "MBEDTLS_AESNI_C":
      if (helper_stfcf_cipher_cdt(config, [], []) || helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal', 'kwe']) || helper_stfcf_key_agre_cdt(config, [], ['alt_hal', 'kwe']) || helper_stfcf_asym_sign_cdt(config, [], ['alt_hal', 'kwe']) || helper_stfcf_mess_auth_cdt(config, ['cmac'], ['mbedtls', 'alt_stcryptolib']) || helper_stfcf_hash_cdt(config, [], ['alt_hal', 'kwe']) || helper_stfcf_random_cdt(config, [], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_AESNI_C";
      } else {
        result = "/* #define MBEDTLS_AESNI_C */";
      }
      break;
    case "MBEDTLS_AES_ALT":
      /* Check for DRBG mode in config if available */
      if (config?.core?.basic?.implementations?.aes_impl == 'alt_hal' ||
          config?.core?.basic?.implementations?.aes_impl == 'alt_stcryptolib' ||
          config?.core?.basic?.implementations?.aes_impl == 'kwe' ||
          helper_stfcf_asym_encr_rsa_cdt(config, ['no_crt'], ['kwe']) ||
          helper_stfcf_asym_sign_cdt(config, ['rsa_sign_verify_1_5.no_crt','rsa_sign_verify_2_2.no_crt','ecdsa_sign_verify'], ['kwe']) ||
          helper_stfcf_key_agre_cdt(config, [], ['kwe'])) {
        result = "#define MBEDTLS_AES_ALT";
      } else {
        result = "/* #define MBEDTLS_AES_ALT */";
      }
      break;
    case "MBEDTLS_AES_C":
      if (config?.core?.advanced?.psa_init?.drbg_mode == 'drbg_ctr' ||
          helper_stfcf_cipher_cdt(config, [], []) ||
          helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_key_agre_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_asym_sign_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_mess_auth_cdt(config, ['cmac'], ['mbedtls', 'alt_stcryptolib']) ||
          helper_stfcf_mess_auth_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_hash_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_random_cdt(config, [], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_AES_C";
      } else {
        result = "/* #define MBEDTLS_AES_C */";
      }
      break;
    case "MBEDTLS_ASN1_PARSE_C":
      if (helper_stfcf_key_agre_cdt(config, [], []) || helper_stfcf_asym_encr_rsa_cdt(config, [], []) || helper_stfcf_asym_sign_cdt(config, [], [])) {
        result = "#define MBEDTLS_ASN1_PARSE_C";
      } else {
        result = "/* #define MBEDTLS_ASN1_PARSE_C */";
      }
      break;
    case "MBEDTLS_ASN1_WRITE_C":
      if (helper_stfcf_key_agre_cdt(config, [], []) || helper_stfcf_asym_encr_rsa_cdt(config, [], []) || helper_stfcf_asym_sign_cdt(config, [], [])) {
        result = "#define MBEDTLS_ASN1_WRITE_C";
      } else {
        result = "/* #define MBEDTLS_ASN1_WRITE_C */";
      }
      break;
    case "MBEDTLS_BASE64_C":
      if (helper_stfcf_key_agre_cdt(config, ['ecdh'], [])) {
        result = "#define MBEDTLS_BASE64_C";
      } else {
        result = "/* #define MBEDTLS_BASE64_C */";
      }
      break;
    case "MBEDTLS_BIGNUM_C":
      if (helper_stfcf_asym_encr_rsa_cdt(config, ['crt', 'no_crt'], []) || helper_stfcf_asym_sign_cdt(config, [], []) || helper_stfcf_key_agre_cdt(config, ['ecdh'], [])) {
        result = "#define MBEDTLS_BIGNUM_C";
      } else {
        result = "/* #define MBEDTLS_BIGNUM_C */";
      }
      break;
    case "MBEDTLS_CCM_C":
      if (config.core?.basic?.cryptography?.cipher?.ccm) {
        result = "#define MBEDTLS_CCM_C";
      } else {
        result = "/* #define MBEDTLS_CCM_C */";
      }
      break;
    case "MBEDTLS_CCM_ALT":
      if (helper_stfcf_cipher_cdt(config, ['ccm'], ['alt_hal'])) {
        result = "#define MBEDTLS_CCM_ALT";
      } else {
        result = "/* #define MBEDTLS_CCM_ALT */";
      }
      break;
    case "MBEDTLS_CHACHA20_C":
      if (helper_stfcf_cipher_cdt(config, ['chachapoly'], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_CHACHA20_C";
      } else {
        result = "/* #define MBEDTLS_CHACHA20_C */";
      }
      break;
    case "MBEDTLS_CHACHAPOLY_ALT":
      if (helper_stfcf_cipher_cdt(config, ['chachapoly'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_CHACHAPOLY_ALT";
      } else {
        result = "/* #define MBEDTLS_CHACHAPOLY_ALT */";
      }
      break;
    case "MBEDTLS_CHACHAPOLY_C":
      if (helper_stfcf_cipher_cdt(config, ['chachapoly'], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_CHACHAPOLY_C";
      } else {
        result = "/* #define MBEDTLS_CHACHAPOLY_C */";
      }
      break;
    case "MBEDTLS_CIPHER_C":
      if (helper_stfcf_cipher_cdt(config, [], []) || helper_stfcf_mess_auth_cdt(config, ['cmac'], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_CIPHER_C";
      } else {
        result = "/* #define MBEDTLS_CIPHER_C */";
      }
      break;
    case "MBEDTLS_CIPHER_MODE_CBC":
      if (helper_stfcf_cipher_cdt(config, ['cbc','ecb'], [])) {
        result = "#define MBEDTLS_CIPHER_MODE_CBC";
      } else {
        result = "/* #define MBEDTLS_CIPHER_MODE_CBC */";
      }
      break;
    case "MBEDTLS_CIPHER_MODE_CTR":
      if (helper_stfcf_cipher_cdt(config, ['ctr'], ['!kwe'])) {
        result = "#define MBEDTLS_CIPHER_MODE_CTR";
      } else {
        result = "/* #define MBEDTLS_CIPHER_MODE_CTR */";
      }
      break;
    case "MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS":
      if (helper_stfcf_cipher_cdt(config, ['cbc','ecb'], []) || helper_stfcf_mess_auth_cdt(config, ['cmac'], ['!alt_hal'])) {
        result = "#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS";
      } else {
        result = "/* #define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS */";
      }
      break;
    case "MBEDTLS_CIPHER_PADDING_PKCS7":
      if (helper_stfcf_cipher_cdt(config, [], []) || helper_stfcf_mess_auth_cdt(config, ['cmac'], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_CIPHER_PADDING_PKCS7";
      } else {
        result = "/* #define MBEDTLS_CIPHER_PADDING_PKCS7 */";
      }
      break;
    case "MBEDTLS_CIPHER_PADDING_ZEROS":
      if (helper_stfcf_cipher_cdt(config, ['cbc','ecb'], []) || helper_stfcf_mess_auth_cdt(config, ['cmac'], ['!alt_hal'])) {
        result = "#define MBEDTLS_CIPHER_PADDING_ZEROS";
      } else {
        result = "/* #define MBEDTLS_CIPHER_PADDING_ZEROS */";
      }
      break;
    case "MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN":
      if (helper_stfcf_cipher_cdt(config, ['cbc','ecb'], []) || helper_stfcf_mess_auth_cdt(config, ['cmac'], ['!alt_hal'])) {
        result = "#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN";
      } else {
        result = "/* #define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN */";
      }
      break;
    case "MBEDTLS_CMAC_C":
      if (helper_stfcf_mess_auth_cdt(config, ['cmac'], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_CMAC_C";
      } else {
        result = "/* #define MBEDTLS_CMAC_C */";
      }
      break;
    case "MBEDTLS_CTR_DRBG_C":
      if (config?.core?.advanced?.psa_init?.drbg_mode == 'drbg_ctr' ||
          helper_stfcf_cipher_cdt(config, ['!chachapoly', '!ctr'], ['alt_hal', 'kwe']) ||
          helper_stfcf_cipher_cdt(config, ['ctr'], ['alt_hal']) ||
          helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_key_agre_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_asym_sign_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_mess_auth_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_hash_cdt(config, [], ['alt_hal', 'kwe']) ||
          helper_stfcf_random_cdt(config, ['ctr'], [])) {
        result = "#define MBEDTLS_CTR_DRBG_C";
      } else {
        result = "/* #define MBEDTLS_CTR_DRBG_C */";
      }
      break;
    case "MBEDTLS_DEPRECATED_REMOVED":
        result = "#define MBEDTLS_DEPRECATED_REMOVED";
      break;
    case "MBEDTLS_ECDH_C":
      if (helper_stfcf_key_agre_cdt(config, ['ecdh'], [])) {
        result = "#define MBEDTLS_ECDH_C";
      } else {
        result = "/* #define MBEDTLS_ECDH_C */";
      }
      break;
    case "MBEDTLS_ECDH_COMPUTE_SHARED_ALT":
      if (helper_stfcf_key_agre_cdt(config, ['ecdh'], ['alt_hal', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT";
      } else {
        result = "/* #define MBEDTLS_ECDH_COMPUTE_SHARED_ALT */";
      }
      break;
    case "MBEDTLS_ECDSA_C":
      if (helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_ECDSA_C";
      } else {
        result = "/* #define MBEDTLS_ECDSA_C */";
      }
      break;
    case "MBEDTLS_ECDSA_DETERMINISTIC":
      if (helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], ['!kwe'])) {
        result = "#define MBEDTLS_ECDSA_DETERMINISTIC";
      } else {
        result = "/* #define MBEDTLS_ECDSA_DETERMINISTIC */";
      }
      break;
    case "MBEDTLS_ECDSA_SIGN_ALT":
      if (helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], ['alt_hal', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_ECDSA_SIGN_ALT";
      } else {
        result = "/* #define MBEDTLS_ECDSA_SIGN_ALT */";
      }
      break;
    case "MBEDTLS_ECDSA_VERIFY_ALT":
      if (helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify', 'rsa_sign_verify_1_5.no_crt', 'rsa_sign_verify_2_2.no_crt'], ['alt_hal', 'alt_stcryptolib','kwe'])) {
        result = "#define MBEDTLS_ECDSA_VERIFY_ALT";
      } else {
        result = "/* #define MBEDTLS_ECDSA_VERIFY_ALT */";
      }
      break;
    case "MBEDTLS_ECP_ALT":
      if (helper_stfcf_key_agre_cdt(config, ['ecdh'], ['alt_hal', 'kwe']) || helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], ['alt_hal', 'kwe'])) {
        result = "#define MBEDTLS_ECP_ALT";
      } else {
        result = "/* #define MBEDTLS_ECP_ALT */";
      }
      break;
    case "MBEDTLS_ECP_C":
      if (helper_stfcf_key_agre_cdt(config, ['ecdh'], []) || helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_ECP_C";
      } else {
        result = "/* #define MBEDTLS_ECP_C */";
      }
      break;
    case "MBEDTLS_HAVE_ASM":
      if (true) {
        result = "#define MBEDTLS_HAVE_ASM";
      } else {
        result = "/* #define MBEDTLS_HAVE_ASM */";
      }
      break;
    case "MBEDTLS_ENTROPY_C":
        result = "#define MBEDTLS_ENTROPY_C";
      break;
    case "MBEDTLS_ENTROPY_HARDWARE_ALT":
      if ((config.core.basic.random.implementation != 'alt_stcryptolib') ||
          (config.core.basic.random.implementation == 'alt_stcryptolib' && config.core.basic.random.drbg != 'ctr' && config.core.basic.random.drbg != 'hmac')) {
        result = "#define MBEDTLS_ENTROPY_HARDWARE_ALT";
      } else {
        result = "/* #define MBEDTLS_ENTROPY_HARDWARE_ALT */";
      }
      break;
    case "MBEDTLS_CMAC_ALT":
      if (helper_stfcf_mess_auth_cdt(config, ['cmac'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_CMAC_ALT";
      } else {
        result = "/* #define MBEDTLS_CMAC_ALT */";
      }
      break;
    case "MBEDTLS_GCM_ALT":
      if (helper_stfcf_cipher_cdt(config, ['gcm'], ['alt_stcryptolib', 'alt_hal'])) {
        result = "#define MBEDTLS_GCM_ALT";
      } else {
        result = "/* #define MBEDTLS_GCM_ALT */";
      }
      break;
    case "MBEDTLS_GCM_C":
      if (config.core?.basic?.cryptography?.cipher?.gcm) {
        result = "#define MBEDTLS_GCM_C";
      } else {
        result = "/* #define MBEDTLS_GCM_C */";
      }
      break;
    case "MBEDTLS_HMAC_DRBG_C":
      if (config?.core?.advanced?.psa_init?.drbg_mode == 'drbg_hmac' ||
          helper_stfcf_cipher_cdt(config, [], ['mbedtls', 'alt_stcryptolib']) ||
          helper_stfcf_asym_encr_rsa_cdt(config, [], ['mbedtls', 'alt_stcryptolib']) ||
          helper_stfcf_key_agre_cdt(config, [], ['mbedtls', 'alt_hal', 'alt_stcryptolib']) ||
          helper_stfcf_asym_sign_cdt(config, [], ['mbedtls', 'alt_stcryptolib']) ||
          helper_stfcf_mess_auth_cdt(config, [], ['mbedtls', 'alt_stcryptolib']) ||
          helper_stfcf_hash_cdt(config, [], ['mbedtls', 'alt_stcryptolib']) ||
          helper_stfcf_random_cdt(config, ['hmac'], ['mbedtls','alt_stcryptolib']) ||
          helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], ['alt_hal'])) {
        result = "#define MBEDTLS_HMAC_DRBG_C";
      } else {
        result = "/* #define MBEDTLS_HMAC_DRBG_C */";
      }
      break;
    case "MBEDTLS_MD_C":
      if (config?.core?.advanced?.psa_init?.drbg_mode == 'drbg_hmac' ||
          helper_stfcf_cipher_cdt(config, [], []) ||
          helper_stfcf_asym_encr_rsa_cdt(config, [], []) ||
          helper_stfcf_key_agre_cdt(config, [], []) ||
          helper_stfcf_asym_sign_cdt(config, [], []) ||
          helper_stfcf_mess_auth_cdt(config, ['hmac'], ['!kwe']) ||
          helper_stfcf_mess_auth_cdt(config, ['cmac'], ['mbedtls', 'alt_stcryptolib']) ||
          helper_stfcf_hash_cdt(config, [], ['!kwe']) ||
          helper_stfcf_random_cdt(config, [], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_MD_C";
      } else {
        result = "/* #define MBEDTLS_MD_C */";
      }
      break;
    case "MBEDTLS_OID_C":
      if (helper_stfcf_asym_encr_rsa_cdt(config, [], []) || helper_stfcf_asym_sign_cdt(config, ['!ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_OID_C";
      } else {
        result = "/* #define MBEDTLS_OID_C */";
      }
      break;
    case "MBEDTLS_PKCS1_V15":
      if (helper_stfcf_asym_sign_cdt(config, ['!ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_PKCS1_V15";
      } else {
        result = "/* #define MBEDTLS_PKCS1_V15 */";
      }
      break;
    case "MBEDTLS_PKCS1_V21":
      if (helper_stfcf_asym_encr_rsa_cdt(config, [], []) || helper_stfcf_asym_sign_cdt(config, ['rsa_sign_verify_2_2.crt', 'rsa_sign_verify_2_2.no_crt'], [])) {
        result = "#define MBEDTLS_PKCS1_V21";
      } else {
        result = "/* #define MBEDTLS_PKCS1_V21 */";
      }
      break;
    case "MBEDTLS_PK_C":
      if (helper_stfcf_asym_encr_rsa_cdt(config, [], []) || helper_stfcf_asym_sign_cdt(config, ['!ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_PK_C";
      } else {
        result = "/* #define MBEDTLS_PK_C */";
      }
      break;
    case "MBEDTLS_PK_PARSE_C":
      if (helper_stfcf_asym_encr_rsa_cdt(config, [], []) || helper_stfcf_asym_sign_cdt(config, ['!ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_PK_PARSE_C";
      } else {
        result = "/* #define MBEDTLS_PK_PARSE_C */";
      }
      break;
    case "MBEDTLS_PK_PARSE_EC_EXTENDED":
      if (helper_stfcf_key_agre_cdt(config, ['ecdh'], []) || helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_PK_PARSE_EC_EXTENDED";
      } else {
        result = "/* #define MBEDTLS_PK_PARSE_EC_EXTENDED */";
      }
      break;
    case "MBEDTLS_PK_WRITE_C":
      if (helper_stfcf_asym_encr_rsa_cdt(config, [], []) || helper_stfcf_asym_sign_cdt(config, ['!ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_PK_WRITE_C";
      } else {
        result = "/* #define MBEDTLS_PK_WRITE_C */";
      }
      break;
    case "MBEDTLS_POLY1305_C":
      if (helper_stfcf_cipher_cdt(config, ['chachapoly'], ['mbedtls','alt_stcryptolib'])) {
        result = "#define MBEDTLS_POLY1305_C";
      } else {
        result = "/* #define MBEDTLS_POLY1305_C */";
      }
      break;
    case "MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS":
        result = "#define MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS";
      break;
    case "MBEDTLS_PSA_CRYPTO_C":
        result = "#define MBEDTLS_PSA_CRYPTO_C";
      break;
    case "MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG":
      if (helper_stfcf_random_cdt(config, ['ctr'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG";
      } else {
        result = "/* #define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */";
      }
      break;
    case "MBEDTLS_PSA_KEY_STORE_DYNAMIC":
        result = "#define MBEDTLS_PSA_KEY_STORE_DYNAMIC";
      break;
    case "MBEDTLS_RSA_ALT":
      if (helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal', 'alt_stcryptolib']) || helper_stfcf_asym_sign_cdt(config, ['!ecdsa_sign_verify'], ['alt_hal', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_RSA_ALT";
      } else {
        result = "/* #define MBEDTLS_RSA_ALT */";
      }
      break;
    case "MBEDTLS_RSA_C":
      if (helper_stfcf_asym_encr_rsa_cdt(config, [], []) || helper_stfcf_asym_sign_cdt(config, ['!ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_RSA_C";
      } else {
        result = "/* #define MBEDTLS_RSA_C */";
      }
      break;
    case "MBEDTLS_RSA_NO_CRT":
      if (helper_stfcf_asym_encr_rsa_cdt(config, ['no_crt'], ['!kwe']) || helper_stfcf_asym_sign_cdt(config, ['rsa_sign_verify_1_5.no_crt','rsa_sign_verify_2_2.no_crt'], ['!kwe'])) {
        result = "#define MBEDTLS_RSA_NO_CRT";
      } else {
        result = "/* #define MBEDTLS_RSA_NO_CRT */";
      }
      break;
    case "MBEDTLS_SHA224_C":
      if (helper_stfcf_key_agre_cdt(config, ['ecdh'], []) || helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], [])) {
        result = "#define MBEDTLS_SHA224_C";
      } else {
        result = "/* #define MBEDTLS_SHA224_C */";
      }
      break;
    case "MBEDTLS_SHA256_ALT":
      if (config?.core?.basic?.implementations?.sha256_impl == 'alt_stcryptolib' ||
          config?.core?.basic?.implementations?.sha256_impl == 'alt_hal' ||
          helper_stfcf_mess_auth_cdt(config, ['hmac'], ['alt_stcryptolib', 'alt_hal'])) {
        result = "#define MBEDTLS_SHA256_ALT";
      } else {
        result = "/* #define MBEDTLS_SHA256_ALT */";
      }
      break;
    case "MBEDTLS_SHA512_ALT":
      if (helper_stfcf_hash_cdt(config, ['sha384', 'sha512'], ['alt_stcryptolib', 'alt_hal'])) {
        result = "#define MBEDTLS_SHA512_ALT";
      } else {
        result = "/* #define MBEDTLS_SHA512_ALT */";
      }
      break;
    case "MBEDTLS_SHA256_C":
      if (config?.core?.advanced?.psa_init?.drbg_mode == 'drbg_ctr' ||
          config?.core?.advanced?.psa_init?.drbg_mode == 'drbg_hmac' ||
          helper_stfcf_cipher_cdt(config, [], []) ||
          helper_stfcf_asym_encr_rsa_cdt(config, [], []) ||
          helper_stfcf_key_agre_cdt(config, [], []) ||
          helper_stfcf_asym_sign_cdt(config, [], []) ||
          helper_stfcf_mess_auth_cdt(config, ['hmac'], ['!kwe']) ||
          helper_stfcf_mess_auth_cdt(config, ['cmac'], ['mbedtls', 'alt_stcryptolib']) ||
          helper_stfcf_hash_cdt(config, [], ['!kwe']) ||
          helper_stfcf_random_cdt(config, [], ['mbedtls', 'alt_stcryptolib'])) {
        result = "#define MBEDTLS_SHA256_C";
      } else {
        result = "/* #define MBEDTLS_SHA256_C */";
      }
      break;
    case "MBEDTLS_SHA384_C":
      if (helper_stfcf_hash_cdt(config, ['sha384'], [])) {
        result = "#define MBEDTLS_SHA384_C";
      } else {
        result = "/* #define MBEDTLS_SHA384_C */";
      }
      break;
    case "MBEDTLS_SHA512_C":
      if (helper_stfcf_hash_cdt(config, ['sha512'], [])) {
        result = "#define MBEDTLS_SHA512_C";
      } else {
        result = "/* #define MBEDTLS_SHA512_C */";
      }
      break;
    case "MBEDTLS_PLATFORM_C":
        result = "#define MBEDTLS_PLATFORM_C";
      break;
    case "MBEDTLS_VERSION_C":
        result = "#define MBEDTLS_VERSION_C";
      break;
    case "MBEDTLS_VERSION_FEATURES":
        result = "#define MBEDTLS_VERSION_FEATURES";
      break;
    /* HAL ALT flags */
    case "MBEDTLS_HAL_AES_ALT":
      if (config?.core?.basic?.implementations?.aes_impl == 'alt_hal' ||
          config?.core?.basic?.implementations?.aes_impl == 'kwe' ||
          helper_stfcf_asym_encr_rsa_cdt(config, ['no_crt'], ['kwe']) ||
          helper_stfcf_asym_sign_cdt(config, ['rsa_sign_verify_1_5.no_crt','rsa_sign_verify_2_2.no_crt','ecdsa_sign_verify'], ['kwe']) ||
          helper_stfcf_key_agre_cdt(config, [], ['kwe'])) {
        result = "#define MBEDTLS_HAL_AES_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_AES_ALT */";
      }
      break;
    case "MBEDTLS_HAL_CCM_ALT":
      if (helper_stfcf_cipher_cdt(config, ['ccm'], ['alt_hal'])) {
        result = "#define MBEDTLS_HAL_CCM_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_CCM_ALT */";
      }
      break;
    case "MBEDTLS_HAL_ECDH_ALT":
      if (helper_stfcf_key_agre_cdt(config, ['ecdh'], ['alt_hal'])) {
        result = "#define MBEDTLS_HAL_ECDH_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_ECDH_ALT */";
      }
      break;
    case "MBEDTLS_HAL_ECDSA_ALT":
      if (helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify', 'rsa_sign_verify_1_5.no_crt', 'rsa_sign_verify_2_2.no_crt'], ['alt_hal', 'kwe'])) {
        result = "#define MBEDTLS_HAL_ECDSA_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_ECDSA_ALT */";
      }
      break;
    case "MBEDTLS_HAL_ECP_ALT":
      if ((helper_stfcf_key_agre_cdt(config, ['ecdh'], ['alt_hal','kwe']) || helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], ['alt_hal','kwe']))) {
        result = "#define MBEDTLS_HAL_ECP_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_ECP_ALT */";
      }
      break;
    /* Always enabled! */
    case "MBEDTLS_HAL_ENTROPY_HARDWARE_ALT":
      if (true) {
        result = "#define MBEDTLS_HAL_ENTROPY_HARDWARE_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_ENTROPY_HARDWARE_ALT */";
      }
      break;
    case "MBEDTLS_NO_PLATFORM_ENTROPY":
      result = "#define MBEDTLS_NO_PLATFORM_ENTROPY";
      break;
    case "MBEDTLS_HAL_GCM_ALT":
      if (helper_stfcf_cipher_cdt(config, ['gcm'], ['alt_hal'])) {
        result = "#define MBEDTLS_HAL_GCM_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_GCM_ALT */";
      }
      break;
    case "MBEDTLS_HAL_RSA_ALT":
      if ((helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal']) || helper_stfcf_asym_sign_cdt(config, ['!ecdsa_sign_verify'], ['alt_hal']))) {
        result = "#define MBEDTLS_HAL_RSA_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_RSA_ALT */";
      }
      break;
    case "MBEDTLS_SHA1_C":
      if (helper_stfcf_hash_cdt(config, ['sha1'], [])) {
        result = "#define MBEDTLS_SHA1_C";
      } else {
        result = "/* #define MBEDTLS_SHA1_C */";
      }
      break;
    case "MBEDTLS_SHA1_ALT":
      if (helper_stfcf_hash_cdt(config, ['sha1'], ['alt_hal'])) {
        result = "#define MBEDTLS_SHA1_ALT";
      } else {
        result = "/* #define MBEDTLS_SHA1_ALT */";
      }
      break;
    case "MBEDTLS_HAL_SHA1_ALT":
      if (helper_stfcf_hash_cdt(config, ['sha1'], ['alt_hal'])) {
        result = "#define MBEDTLS_HAL_SHA1_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_SHA1_ALT */";
      }
      break;
    case "MBEDTLS_HAL_SHA256_ALT":
      if (config?.core?.basic?.implementations?.sha256_impl == 'alt_hal') {
        result = "#define MBEDTLS_HAL_SHA256_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_SHA256_ALT */";
      }
      break;
    case "MBEDTLS_HAL_SHA512_ALT":
      if (helper_stfcf_hash_cdt(config, ['sha384','sha512'], ['alt_hal'])) {
        result = "#define MBEDTLS_HAL_SHA512_ALT";
      } else {
        result = "/* #define MBEDTLS_HAL_SHA512_ALT */";
      }
      break;
    /* STCRYPTOLIB ALT flags */
    case "MBEDTLS_STCRYPTOLIB_AES_ALT":
      if (config?.core?.basic?.implementations?.aes_impl == 'alt_stcryptolib') {
        result = "#define MBEDTLS_STCRYPTOLIB_AES_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_AES_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_CCM_ALT":
      if (helper_stfcf_cipher_cdt(config, ['ccm'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_STCRYPTOLIB_CCM_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_CCM_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT":
      if (helper_stfcf_cipher_cdt(config, ['chachapoly'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_CHACHAPOLY_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_CMAC_ALT":
      if (helper_stfcf_mess_auth_cdt(config, ['cmac'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_STCRYPTOLIB_CMAC_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_CMAC_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_DRBG_ALT":
      if (helper_stfcf_random_cdt(config, ['ctr'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_STCRYPTOLIB_DRBG_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_DRBG_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_ECDH_ALT":
      if (helper_stfcf_key_agre_cdt(config, ['ecdh'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_STCRYPTOLIB_ECDH_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_ECDH_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_ECDSA_ALT":
      if (helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_STCRYPTOLIB_ECDSA_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_ECDSA_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_GCM_ALT":
      if (helper_stfcf_cipher_cdt(config, ['gcm'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_STCRYPTOLIB_GCM_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_GCM_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_RSA_ALT":
      if (helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_stcryptolib']) ||
          helper_stfcf_asym_sign_cdt(config, ['!ecdsa_sign_verify'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_STCRYPTOLIB_RSA_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_RSA_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_SHA256_ALT":
      if (config?.core?.basic?.implementations?.sha256_impl == 'alt_stcryptolib') {
        result = "#define MBEDTLS_STCRYPTOLIB_SHA256_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_SHA256_ALT */";
      }
      break;
    case "MBEDTLS_STCRYPTOLIB_SHA512_ALT":
      if (helper_stfcf_hash_cdt(config, ['sha384','sha512'], ['alt_stcryptolib'])) {
        result = "#define MBEDTLS_STCRYPTOLIB_SHA512_ALT";
      } else {
        result = "/* #define MBEDTLS_STCRYPTOLIB_SHA512_ALT */";
      }
      break;
    /* KWE flags */
    case "KWE_DRIVER_ENABLED":
      if (helper_stfcf_cipher_cdt(config, ['!ctr', '!chachapoly'], ['kwe']) || helper_stfcf_key_agre_cdt(config, ['ecdh'], ['kwe']) || helper_stfcf_asym_sign_cdt(config, ['rsa_sign_verify_1_5.no_crt','rsa_sign_verify_2_2.no_crt','ecdsa_sign_verify'], ['kwe']) || helper_stfcf_asym_encr_rsa_cdt(config, ['no_crt'], ['kwe'])) {
        result = "#define KWE_DRIVER_ENABLED";
      } else {
        result = "/* #define KWE_DRIVER_ENABLED */";
      }
      break;
    case "PSA_KWE_DRIVER_ENABLED":
      if (helper_stfcf_cipher_cdt(config, ['!ctr', '!chachapoly'], ['kwe']) || helper_stfcf_key_agre_cdt(config, ['ecdh'], ['kwe']) || helper_stfcf_asym_sign_cdt(config, ['rsa_sign_verify_1_5.no_crt','rsa_sign_verify_2_2.no_crt','ecdsa_sign_verify'], ['kwe']) || helper_stfcf_asym_encr_rsa_cdt(config, ['no_crt'], ['kwe'])) {
        result = "#define PSA_KWE_DRIVER_ENABLED";
      } else {
        result = "/* #define PSA_KWE_DRIVER_ENABLED */";
      }
      break;
    case "KWE_ASYMMETRIC_KEY_WRAP_ENABLED":
      if (helper_stfcf_asym_encr_rsa_cdt(config, ['no_crt'], ['kwe']) ||
          helper_stfcf_asym_sign_cdt(config, ['rsa_sign_verify_1_5.no_crt','rsa_sign_verify_2_2.no_crt','ecdsa_sign_verify'], ['kwe']) ||
          helper_stfcf_key_agre_cdt(config, [], ['kwe'])) {
        result = "#define KWE_ASYMMETRIC_KEY_WRAP_ENABLED";
      } else {
        result = "/* #define KWE_ASYMMETRIC_KEY_WRAP_ENABLED */";
      }
      break;
    case "KWE_SYMMETRIC_KEY_WRAP_ENABLED":
      if (helper_stfcf_cipher_cdt(config, ['!ctr', '!chachapoly'], ['kwe'])) {
        result = "#define KWE_SYMMETRIC_KEY_WRAP_ENABLED";
      } else {
        result = "/* #define KWE_SYMMETRIC_KEY_WRAP_ENABLED */";
      }
      break;
    case "KWE_USE_CBC_TO_WRAP_SYMMETRIC_KEY":
      if (config?.core?.advanced?.kwe_config?.wrap_aes_cbc_symetric_key) {
        result = "#define KWE_USE_CBC_TO_WRAP_SYMMETRIC_KEY";
      } else {
        result = "/* #define KWE_USE_CBC_TO_WRAP_SYMMETRIC_KEY */";
      }
      break;
    case "KWE_ECP_SHORT_WEIERSTRASS_ENABLED":
      if (config?.core?.advanced?.kwe_config?.kwe_ecp_short_weierstrass) {
        result = "#define KWE_ECP_SHORT_WEIERSTRASS_ENABLED";
      } else {
        result = "/* #define KWE_ECP_SHORT_WEIERSTRASS_ENABLED */";
      }
      break;
    /* Elliptic curves flags */
    case "MBEDTLS_ECP_DP_SECP192R1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.secp192r1) {
        result = "#define MBEDTLS_ECP_DP_SECP192R1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_SECP192R1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_SECP224R1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.secp224r1) {
        result = "#define MBEDTLS_ECP_DP_SECP224R1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_SECP224R1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_SECP256R1_ENABLED":
      if (helper_stfcf_asym_sign_cdt(config, ['ecdsa_sign_verify'], []) ||
          helper_stfcf_key_agre_cdt(config, ['ecdh'], []) ||
          config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.secp256r1) {
        result = "#define MBEDTLS_ECP_DP_SECP256R1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_SECP256R1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_SECP384R1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.secp384r1) {
        result = "#define MBEDTLS_ECP_DP_SECP384R1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_SECP384R1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_SECP521R1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.secp521r1) {
        result = "#define MBEDTLS_ECP_DP_SECP521R1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_SECP521R1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_SECP192K1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.secp192k1) {
        result = "#define MBEDTLS_ECP_DP_SECP192K1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_SECP192K1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_SECP224K1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.secp224k1) {
        result = "#define MBEDTLS_ECP_DP_SECP224K1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_SECP224K1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_SECP256K1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.secp256k1) {
        result = "#define MBEDTLS_ECP_DP_SECP256K1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_SECP256K1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_BP256R1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.bp256r1) {
        result = "#define MBEDTLS_ECP_DP_BP256R1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_BP256R1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_BP384R1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.bp384r1) {
        result = "#define MBEDTLS_ECP_DP_BP384R1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_BP384R1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_BP512R1_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.short_weierstrass_curves?.bp512r1) {
        result = "#define MBEDTLS_ECP_DP_BP512R1_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_BP512R1_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_CURVE25519_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.montgomery_curves?.curve25519) {
        result = "#define MBEDTLS_ECP_DP_CURVE25519_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_CURVE25519_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_DP_CURVE448_ENABLED":
      if (config?.core?.advanced?.mbedtls_elliptic_curves?.montgomery_curves?.curve448) {
        result = "#define MBEDTLS_ECP_DP_CURVE448_ENABLED";
      } else {
        result = "/* #define MBEDTLS_ECP_DP_CURVE448_ENABLED */";
      }
      break;
    case "MBEDTLS_ECP_NIST_OPTIM":
      if (helper_stfcf_asym_sign_cdt(config, [], ['mbedtls','alt_stcryptolib']) ||
          helper_stfcf_key_agre_cdt(config, [], ['mbedtls','alt_stcryptolib'])) {
        result = "#define MBEDTLS_ECP_NIST_OPTIM";
      } else {
        result = "/* #define MBEDTLS_ECP_NIST_OPTIM */";
      }
      break;
    case "MBEDTLS_MEMORY_BUFFER_ALLOC_C":
      if (config?.core?.advanced?.mbedtls_platform_management?.mem_buff_allocator) {
        result = "#define MBEDTLS_MEMORY_BUFFER_ALLOC_C";
      } else {
        result = "/* #define MBEDTLS_MEMORY_BUFFER_ALLOC_C */";
      }
      break;
    case "MBEDTLS_PLATFORM_MEMORY":
      if (config?.core?.advanced?.mbedtls_platform_management?.mem_buff_allocator) {
        result = "#define MBEDTLS_PLATFORM_MEMORY";
      } else {
        result = "/* #define MBEDTLS_PLATFORM_MEMORY */";
      }
      break;
    default:
      result = `/* #define ${flag} */`;
      break;
    }
  return result;
}

/**
 * Checks whether KWE-related features are enabled in the configuration or not.
 * @param {config} config
 * @returns boolean
 */
function helper_stfcf_mbedtlsconfig_kwe_enabled ( config )  {
  let result = "";
    if (helper_stfcf_cipher_cdt(config, ['!ctr', '!chachapoly'], ['kwe']) ||
        helper_stfcf_key_agre_cdt(config, ['ecdh'], ['kwe']) ||
        helper_stfcf_asym_sign_cdt(config, ['rsa_sign_verify_1_5.no_crt','rsa_sign_verify_2_2.no_crt','ecdsa_sign_verify'], ['kwe']) ||
        helper_stfcf_asym_encr_rsa_cdt(config, ['no_crt'], ['kwe'])) {
      console.debug(`helper_stfcf_mbedtlsconfig_kwe_enabled return true`);
      result = true;
    } else {
      console.debug(`helper_stfcf_mbedtlsconfig_kwe_enabled return false`);
      result = false;
    }
  return result;
}

/**
 * Checks whether any of the AES ALT implementations is enabled in the configuration or not.
 * @param {mbedtls_aes_alt} config
 * @returns boolean
 */
function helper_stfcf_aes_alt ( config )  {
  let result = "";
    if ($fcf_mw.helper_stfcf_cipher_cdt(config, [], ['alt_hal', 'alt_stcryptolib']) ||
        $fcf_mw.helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal', 'kwe']) ||
        $fcf_mw.helper_stfcf_key_agre_cdt(config, [], ['alt_hal', 'kwe']) ||
        $fcf_mw.helper_stfcf_asym_sign_cdt(config, [], ['alt_hal', 'kwe']) ||
        $fcf_mw.helper_stfcf_mess_auth_cdt(config, ['cmac'], ['alt_stcryptolib']) ||
        $fcf_mw.helper_stfcf_hash_cdt(config, [], ['alt_hal', 'kwe'])) {
      console.debug(`helper_stfcf_aes_alt return true`);
      result = true;
    } else {
      console.debug(`helper_stfcf_aes_alt return false`);
      result = false;
    }
  return result;
}

/**
 * Checks whether HAL-based AES alternative logic is enabled or not.
 * @param {mbedtls_hal_aes_alt} config
 * @returns boolean
 */
function helper_stfcf_aes_alt_hal ( config )  {
  let result = "";
    if ((helper_stfcf_cipher_cdt(config, ['!ccm', '!gcm', '!chachapoly'], ['alt_hal']) ||
         helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal']) ||
         helper_stfcf_asym_encr_rsa_cdt(config, ['no_crt'], ['kwe']) ||
         helper_stfcf_asym_sign_cdt(config, [], ['alt_hal']) ||
         helper_stfcf_asym_sign_cdt(config, ['rsa_sign_verify_1_5.no_crt','rsa_sign_verify_2_2.no_crt','ecdsa_sign_verify'], ['kwe']) ||
         helper_stfcf_key_agre_cdt(config, [], ['alt_hal','kwe']) ||
         helper_stfcf_mess_auth_cdt(config, ['hmac'], ['alt_hal']) ||
         helper_stfcf_hash_cdt(config, [], ['alt_hal']))) {
      console.debug(`helper_stfcf_aes_alt_hal return true`);
      result = true;
    } else {
      console.debug(`helper_stfcf_aes_alt_hal return false`);
      result = false;
    }
  return result;
}

/**
 * Checks whether STCRYPTOLIB-based AES alternative logic is enabled or not.
 * @param {mbedtls_stcryptolib_aes_alt} config
 * @returns boolean
 */
function helper_stfcf_aes_alt_stcryptolib ( config )  {
  let result = "";
    if ($fcf_mw.helper_stfcf_cipher_cdt(config, [], ['alt_stcryptolib']) ||
        $fcf_mw.helper_stfcf_mess_auth_cdt(config, ['cmac'], ['alt_stcryptolib'])) {
      console.debug(`helper_stfcf_aes_alt_stcryptolib return true`);
      result = true;
    } else {
      console.debug(`helper_stfcf_aes_alt_stcryptolib return false`);
      result = false;
    }
  return result;
}

/**
 * Checks whether HAL-based AES-CCM alternative logic is enabled or not.
 * @param {mbedtls_hal_ccm_alt} config
 * @returns boolean
 */
function helper_stfcf_aes_ccm_alt_hal ( config )  {
  let result = "";
    if (helper_stfcf_cipher_cdt(config, ['ccm'], ['alt_hal','kwe'])) {
      console.debug(`helper_stfcf_aes_ccm_alt_hal return true`);
      result = true;
    } else {
      console.debug(`helper_stfcf_aes_ccm_alt_hal return false`);
      result = false;
    }
  return result;
}

/**
 * Checks whether HAL-based AES-GCM alternative logic is enabled or not.
 * @param {mbedtls_hal_gcm_alt} config
 * @returns boolean
 */
function helper_stfcf_aes_gcm_alt_hal ( config )  {
  let result = "";
    if (helper_stfcf_cipher_cdt(config, ['gcm'], ['alt_hal','kwe'])) {
      console.debug(`helper_stfcf_aes_gcm_alt_hal return true`);
      result = true;
    } else {
      console.debug(`helper_stfcf_aes_gcm_alt_hal return false`);
      result = false;
    }
  return result;
}

/**
 * Checks whether HAL-based SHA-1 or SHA-256 alternative logic is enabled or not.
 * @param {mbedtls_hal_sha1_alt or mbedtls_hal_sha256_alt} config
 * @returns boolean
 */
function helper_stfcf_sha1_sha256_alt_hal ( config )  {
  let result = "";
    if ((helper_stfcf_cipher_cdt(config, [], ['alt_hal', 'kwe']) ||
         helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal', 'kwe']) ||
         helper_stfcf_key_agre_cdt(config, [], ['alt_hal', 'kwe']) ||
         helper_stfcf_asym_sign_cdt(config, [], ['alt_hal', 'kwe']) ||
         helper_stfcf_mess_auth_cdt(config, ['hmac'], ['alt_hal', 'kwe']) ||
         helper_stfcf_hash_cdt(config, ['sha224','sha256'], ['alt_hal', 'kwe']))) {
      console.debug(`helper_stfcf_sha1_sha256_alt_hal return true`);
      result = true;
    } else {
      console.debug(`helper_stfcf_sha1_sha256_alt_hal return false`);
      result = false;
    }
  return result;
}

/**
 * Checks whether HAL-based ECDH, ECDSA, ECP or RSA alternative logic is enabled or not.
 * @param {mbedtls_hal_ecdsa_alt or
 *         mbedtls_hal_ecdh_alt or
 *         mbedtls_hal_ecp_alt or
 *         mbedtls_hal_rsa_alt} config
 * @returns boolean
 */
function helper_stfcf_ecdh_ecdsa_ecp_rsa_alt_hal ( config )  {
  let result = "";
    if (helper_stfcf_key_agre_cdt(config, ['ecdh'], ['alt_hal','kwe']) ||
        helper_stfcf_asym_sign_cdt(config, [], ['alt_hal','kwe']) ||
        helper_stfcf_asym_encr_rsa_cdt(config, [], ['alt_hal'])) {
      console.debug(`helper_stfcf_ecdh_ecdsa_ecp_rsa_alt_hal return true`);
      result = true;
    } else {
      console.debug(`helper_stfcf_ecdh_ecdsa_ecp_rsa_alt_hal return false`);
      result = false;
    }
  return result;
}

module.exports = {
  helper_stfcf_get_generated_function_name,
  helper_stfcf_cipher_cdt,
  helper_stfcf_asym_encr_rsa_cdt,
  helper_stfcf_key_agre_cdt,
  helper_stfcf_asym_sign_cdt,
  helper_stfcf_mess_auth_cdt,
  helper_stfcf_hash_cdt,
  helper_stfcf_random_cdt,
  helper_stfcf_mbedtlsconfig_switch,
  helper_stfcf_mbedtlsconfig_kwe_enabled,
  helper_stfcf_aes_alt,
  helper_stfcf_aes_alt_hal,
  helper_stfcf_aes_alt_stcryptolib,
  helper_stfcf_aes_ccm_alt_hal,
  helper_stfcf_aes_gcm_alt_hal,
  helper_stfcf_sha1_sha256_alt_hal,
  helper_stfcf_ecdh_ecdsa_ecp_rsa_alt_hal
};
