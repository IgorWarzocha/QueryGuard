# queryguard/rule_loader.py

"""
Handles loading and basic validation of QueryGuard rule configuration files.
"""
import yaml
from typing import List, Dict, Any, Union, Optional
import os
import logging

# Get a logger for this module
_logger = logging.getLogger(__name__)

# Define expected top-level keys and essential rule keys for validation
EXPECTED_TOP_LEVEL_KEY = "rules"
ESSENTIAL_RULE_KEYS = {
    "rule_id": str,
    "enabled": bool, # Will be validated strictly as bool after initial string conversion
    "severity": str,
    "detection_logic": dict,
    "action_on_match": str,
    "rule_name": str,
    "description": str,
    "message_template": str,
}
ESSENTIAL_DETECTION_LOGIC_KEYS = {
    "check_function": str,
    # Parameters are function-specific, deeper validation is part of IMPROVE-06
    "parameters": (dict, type(None)), # Allow parameters to be optional or a dict
}
ALLOWED_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"]
ALLOWED_ACTIONS = ["ALLOW", "BLOCK", "FLAG", "REQUEST_REPHRASE", "SCORE_ADJUST"]

def _validate_rule(rule: Dict[str, Any], rule_index: int, filepath_for_logging: str) -> List[str]:
    """
    Performs basic validation on a single rule dictionary.
    Returns a list of validation error messages.
    """
    errors = []
    rule_id_log = rule.get('rule_id', f'UNKNOWN_AT_INDEX_{rule_index+1}')

    for key, expected_type in ESSENTIAL_RULE_KEYS.items():
        if key not in rule:
            # 'enabled' is a special case, can be defaulted if missing
            if key == 'enabled': 
                continue 
            errors.append(f"Rule '{rule_id_log}': Missing essential key '{key}'.")
        elif not isinstance(rule[key], expected_type):
            # Special handling for 'enabled' which might have been converted from string
            if key == 'enabled' and isinstance(rule[key], bool):
                pass # Already correct type after potential conversion
            else:
                errors.append(f"Rule '{rule_id_log}': Key '{key}' has incorrect type. Expected {expected_type.__name__}, got {type(rule[key]).__name__}.")

    detection_logic = rule.get("detection_logic")
    if isinstance(detection_logic, dict):
        for key, expected_types in ESSENTIAL_DETECTION_LOGIC_KEYS.items():
            if key not in detection_logic:
                 # 'parameters' can be optional
                if key == 'parameters':
                    continue
                errors.append(f"Rule '{rule_id_log}': Missing key '{key}' in 'detection_logic'.")
            # isinstance check with a tuple of types
            elif not isinstance(detection_logic[key], expected_types if isinstance(expected_types, tuple) else (expected_types,)):
                 errors.append(f"Rule '{rule_id_log}': Key '{key}' in 'detection_logic' has incorrect type. Expected {expected_types}, got {type(detection_logic[key]).__name__}.")
    elif "detection_logic" in rule: # It exists but is not a dict
         errors.append(f"Rule '{rule_id_log}': 'detection_logic' must be a dictionary.")

    if "severity" in rule and rule.get("severity") not in ALLOWED_SEVERITIES:
        errors.append(f"Rule '{rule_id_log}': Invalid 'severity' value '{rule.get('severity')}'. Allowed: {ALLOWED_SEVERITIES}")
    if "action_on_match" in rule and rule.get("action_on_match") not in ALLOWED_ACTIONS:
        errors.append(f"Rule '{rule_id_log}': Invalid 'action_on_match' value '{rule.get('action_on_match')}'. Allowed: {ALLOWED_ACTIONS}")

    # This check for 'enabled' string values was part of the original logic,
    # ensuring it's a boolean after potential string parsing.
    # The actual string parsing happens in load_rules_from_yaml.
    # Here, we just ensure that if 'enabled' exists, it must be a boolean at this stage of validation.
    if 'enabled' in rule and not isinstance(rule['enabled'], bool):
         errors.append(f"Rule '{rule_id_log}': Key 'enabled' must be a boolean (true/false). Found: '{rule['enabled']}'.")

    return errors

def load_rules_from_yaml(filepath: str) -> List[Dict[str, Any]]:
    """
    Loads rules from a YAML file and performs basic structural validation.
    """
    abs_filepath = os.path.abspath(filepath)
    _logger.info(f"Attempting to load YAML rules from absolute path: {abs_filepath}")

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            rules_data_wrapper = yaml.safe_load(f)
    except FileNotFoundError:
        _logger.error(f"Rule file not found at '{filepath}' (resolved to '{abs_filepath}').", exc_info=True)
        raise
    except yaml.YAMLError as e:
        _logger.error(f"Error parsing YAML rule file '{abs_filepath}': {e}", exc_info=True)
        raise
    except Exception as e: # Catch any other unexpected IO errors
        _logger.error(f"An unexpected error occurred while trying to open or read rule file '{abs_filepath}': {e}", exc_info=True)
        raise ValueError(f"Unexpected error during file/YAML processing for '{abs_filepath}': {e}")

    if not isinstance(rules_data_wrapper, dict) or EXPECTED_TOP_LEVEL_KEY not in rules_data_wrapper:
        msg = f"YAML content in '{abs_filepath}' must be a dictionary with a top-level '{EXPECTED_TOP_LEVEL_KEY}' key."
        _logger.error(msg)
        raise ValueError(msg)

    ruleset_from_yaml = rules_data_wrapper.get(EXPECTED_TOP_LEVEL_KEY, [])
    if not isinstance(ruleset_from_yaml, list):
        msg = f"The '{EXPECTED_TOP_LEVEL_KEY}' key in '{abs_filepath}' must contain a list of rules."
        _logger.error(msg)
        raise ValueError(msg)

    validated_ruleset = []
    all_errors_for_file = []
    for i, rule_dict in enumerate(ruleset_from_yaml):
        if not isinstance(rule_dict, dict):
            all_errors_for_file.append(f"Rule definition at index {i} in '{abs_filepath}' is not a dictionary.")
            continue

        # Handle string 'true'/'false' for 'enabled' field
        if 'enabled' in rule_dict and isinstance(rule_dict['enabled'], str):
            enabled_str = rule_dict['enabled'].lower()
            if enabled_str == 'true':
                rule_dict['enabled'] = True
            elif enabled_str == 'false':
                rule_dict['enabled'] = False
            else:
                # This error will be caught by _validate_rule if it's not a proper boolean by then
                pass 
        elif 'enabled' not in rule_dict: # Default 'enabled' to true if missing
             rule_dict['enabled'] = True

        # Ensure detection_logic and parameters are dicts if they exist
        if "detection_logic" in rule_dict and not isinstance(rule_dict["detection_logic"], dict):
            # This will be caught by _validate_rule more specifically
            pass
        elif "detection_logic" in rule_dict and "parameters" in rule_dict["detection_logic"] and \
             not isinstance(rule_dict["detection_logic"]["parameters"], (dict, type(None))): # Allow None for parameters
            # This will be caught by _validate_rule
            pass

        validation_errors_for_rule = _validate_rule(rule_dict, i, abs_filepath)
        if validation_errors_for_rule:
            for err_msg in validation_errors_for_rule: # Prepend file info if not already there
                all_errors_for_file.append(f"In file '{abs_filepath}', {err_msg}")
        else:
            validated_ruleset.append(rule_dict)

    if all_errors_for_file:
        error_summary = "\n".join(sorted(list(set(all_errors_for_file)))) # Unique errors
        msg = f"Validation failed for rule file '{abs_filepath}' with {len(set(all_errors_for_file))} unique error(s):\n{error_summary}"
        _logger.error(msg)
        raise ValueError(msg)

    _logger.info(f"Successfully loaded and validated {len(validated_ruleset)} rules from '{abs_filepath}'.")
    return validated_ruleset

if __name__ == '__main__':
    # To see output from these tests, the application using QueryGuard (or this script directly)
    # would need to call queryguard.setup_logging()
    # Example from the calling script:
    # import queryguard
    # import logging
    # queryguard.setup_logging(level=logging.DEBUG) # Or logging.INFO

    _logger.info("--- Running QueryGuard Rule Loader Self-Tests ---")

    dummy_valid_rules_content = """
rules:
  - rule_id: "TEST-001"
    rule_name: "Test Rule One"
    description: "A valid test rule."
    enabled: true
    severity: "MEDIUM"
    detection_logic:
      check_function: "detect_direct_injection_variants"
      parameters:
        injection_phrases: ["test phrase"]
        fuzzy_threshold: 80.0
    action_on_match: "FLAG"
    message_template: "Test rule 001 triggered."
  - rule_id: "TEST-002"
    rule_name: "Test Rule Two (Enabled default)"
    description: "Another valid test rule, enabled by default (field missing)."
    severity: "LOW"
    detection_logic:
      check_function: "some_other_check"
      # parameters: null # Example of optional parameters being null
    action_on_match: "ALLOW"
    message_template: "Test rule 002 triggered."
  - rule_id: "TEST-003"
    rule_name: "Test Rule String Enabled"
    description: "Rule with 'enabled' as string."
    enabled: "false" 
    severity: "INFO"
    detection_logic:
      check_function: "some_check"
      parameters: {}
    action_on_match: "FLAG"
    message_template: "Test rule 003 triggered."
"""
    valid_yaml_path = "temp_valid_rules.yaml"
    with open(valid_yaml_path, "w", encoding="utf-8") as f:
        f.write(dummy_valid_rules_content)

    dummy_invalid_rules_content = """
rules:
  - rule_id: "INVALID-001"
    rule_name: "Invalid Rule One"
    description: "An invalid rule."
    # severity: "MISSING" # Missing severity
    enabled: true
    detection_logic: # Missing check_function
      parameters: {}
    action_on_match: "BLOCK"
    message_template: "Invalid rule 001 triggered."
  - rule_id: "INVALID-002"
    rule_name: "Invalid Rule Two"
    description: "Another invalid rule."
    enabled: "yes" # Invalid string for boolean
    severity: "VERY_HIGH" # Invalid severity
    detection_logic:
      check_function: 123 # Invalid type for check_function
      parameters: "not a dict" # Invalid type for parameters
    action_on_match: "DESTROY" # Invalid action
    message_template: "Invalid rule 002 triggered."
"""
    invalid_yaml_path = "temp_invalid_rules.yaml"
    with open(invalid_yaml_path, "w", encoding="utf-8") as f:
        f.write(dummy_invalid_rules_content)

    _logger.info("\n--- Testing rule_loader with VALID file ---")
    try:
        loaded_rules = load_rules_from_yaml(valid_yaml_path)
        for r_idx, r_val in enumerate(loaded_rules):
            _logger.info(f"  Loaded Rule {r_idx+1}: ID={r_val.get('rule_id')}, Enabled={r_val.get('enabled')} (Type: {type(r_val.get('enabled'))})")
    except Exception as e:
        _logger.error(f"  Test FAILED for valid file: {e}", exc_info=True)

    _logger.info("\n--- Testing rule_loader with INVALID file ---")
    try:
        loaded_rules = load_rules_from_yaml(invalid_yaml_path)
        _logger.info(f"  Loaded {len(loaded_rules)} rules (should have failed or loaded 0 if strict).")
    except ValueError as e:
        _logger.info(f"  Test PASSED (as expected) with ValueError. Errors logged above by the loader.")
    except Exception as e:
        _logger.error(f"  Test FAILED for invalid file with unexpected error: {e}", exc_info=True)

    _logger.info("\n--- Testing rule_loader with NONEXISTENT file ---")
    try:
        load_rules_from_yaml("nonexistent_rules.yaml")
    except FileNotFoundError:
        _logger.info("  Test PASSED (as expected) with FileNotFoundError. Error logged above by the loader.")
    except Exception as e:
        _logger.error(f"  Test FAILED for non-existent file with unexpected error: {e}", exc_info=True)

    if os.path.exists(valid_yaml_path): os.remove(valid_yaml_path)
    if os.path.exists(invalid_yaml_path): os.remove(invalid_yaml_path)

    _logger.info("--- Finished QueryGuard Rule Loader Self-Tests ---")
