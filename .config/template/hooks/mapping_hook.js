/**
  ******************************************************************************
  * @file    mapping_hook.js
  * @brief   Mapping hook for STFCF component code generation.
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

/**
  * Mapping hook for STFCF component.
  * Generates code templates conditionally based on STFCF configuration.
  *
  * @param {string}   component_id         identifier of the component being processed
  * @param {array}    component_templates  array of templates available for this component
  * @param {function} _get_hw_instances    function returning hardware instances (not used here)
  * @param {function} get_global_getters_registry function returning global getters registry
  * @param {object}   _cfg_data            configuration data for the current software project (not used here)
  * @param {string}   _secure_ctxt         security context (not used here)
  * @param {string}   _genfileslist_folder output folder path (not used here)
  * @param {function} debug_print          function to output debug logs
  * @param {object}   _strategy            additional strategy parameter (not used here)
  * @return {array} array of mapping rules describing templates to generate
  */
module.exports.main_grouping_hook = function (
  component_id,
  component_templates,
  _get_hw_instances,
  get_global_getters_registry,
  _cfg_data,
  _secure_ctxt,
  _genfileslist_folder,
  debug_print,
  _strategy
) {
  debug_print("################ STFCF HOOK ################");
  debug_print("component_templates", component_templates);

  const globalGetters = get_global_getters_registry();
  const swConfigGettersAPI = globalGetters.swConfigGettersAPI.SWConfigurationAPI;
  const instanceIds = swConfigGettersAPI.getInstances(component_id) || [];
  const instanceConfigs = instanceIds.map(id => swConfigGettersAPI.getSwInstanceConfiguration(id));
  debug_print("instancesConfigs", instanceConfigs);

  /* The template list may contain either 'mx_kwe_config_template.h' or 'mx_kwe_config_template.h.hbs'. */
  const kweTemplate = component_templates.find(t => /mx_kwe_config_template\.h(\.hbs)?$/.test(t));

  /* Add all templates except KWE config unconditionally */
  const hook_result = component_templates
    .filter(template => !kweTemplate || template !== kweTemplate)
    .map(template => getHookResult(component_id, template, getTemplateName(template)));

  /* Check if KWE is enabled in any instance */
  let kwe_enabled = false;
  try {
    const { helper_stfcf_mbedtlsconfig_kwe_enabled } = require('../helpers/stfcf_helpers.js');
    kwe_enabled = instanceConfigs.some(inst => inst && helper_stfcf_mbedtlsconfig_kwe_enabled(inst));
  } catch (e) {
    /* Fallback: advanced-feature section was removed from the schema; rely on core.basic implementation selection. */
    kwe_enabled = instanceConfigs.some(inst => {
      const basic = inst && inst.core && inst.core.basic;
      const implsCfg = basic && basic.implementations;
      if (!implsCfg) return false;

      const impls = Object.values(implsCfg);
      return impls.some(v => v === 'kwe');
    });
    debug_print("[WARN] Could not load stfcf_helpers.js, using fallback KWE detection.", String(e));
  }
  debug_print("STFCF kwe_enabled flag:", kwe_enabled);

  /* Conditionally add KWE config template */
  if (kwe_enabled && kweTemplate) {
    hook_result.push(
      getHookResult(
        component_id,
        kweTemplate,
        getTemplateName(kweTemplate)
      )
    );
  }
  debug_print("STFCF hook_result", hook_result);
  return hook_result;
};

function getTemplateName(templateFileName) {
  return templateFileName
    .replace('_template', '')
    .replace(/\.h\.hbs$/, '.h')
    .replace(/\.c\.hbs$/, '.c')
    .replace(/\.hbs$/, '');
}

function getHookResult(component_id, templateName, outputFileName) {
  return {
    component: component_id,
    resource_type: 'COMPONENT_ENTRY',
    resource: 'no hardware resource',
    template: templateName,
    output: outputFileName,
  };
}
