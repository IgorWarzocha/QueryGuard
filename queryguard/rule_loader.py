# queryguard/rule_loader.py

"""
Handles loading and basic validation of QueryGuard rule configuration files.
"""
import yaml
from typing import List, Dict, Any, Union
import os # Added for os.path.abspath

# Define expected top-level keys and essential rule keys for validation
EXPECTED_TOP_LEVEL_KEY = "rules"
ESSENTIAL_RULE_KEYS = {
    "rule_id": str,
    "enabled": bool,
    "severity": str,
    "detection_logic": dict,
    "action_on_match": str,
    "rule_name": str,
    "description": str,
    "message_template": str,
}
ESSENTIAL_DETECTION_LOGIC_KEYS = {
    "check_function": str,
}
ALLOWED_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"]
ALLOWED_ACTIONS = ["ALLOW", "BLOCK", "FLAG", "REQUEST_REPHRASE", "SCORE_ADJUST"]

def _validate_rule(rule: Dict[str, Any], rule_index: int) -> List[str]:
    """
    Performs basic validation on a single rule dictionary.
    Returns a list of validation error messages.
    """
    errors = []
    for key, expected_type in ESSENTIAL_RULE_KEYS.items():
        if key not in rule:
            errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'UNKNOWN')}): Missing essential key '{key}'.")
        elif not isinstance(rule[key], expected_type):
            if key == 'enabled' and isinstance(rule[key], str) and rule[key].lower() in ['true', 'false']:
                pass 
            else:
                errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Key '{key}' has incorrect type. Expected {expected_type.__name__}, got {type(rule[key]).__name__}.")

    detection_logic = rule.get("detection_logic")
    if isinstance(detection_logic, dict):
        for key, expected_type in ESSENTIAL_DETECTION_LOGIC_KEYS.items():
            if key not in detection_logic:
                errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Missing key '{key}' in 'detection_logic'.")
            elif not isinstance(detection_logic[key], expected_type):
                 errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Key '{key}' in 'detection_logic' has incorrect type. Expected {expected_type.__name__}, got {type(detection_logic[key]).__name__}.")

    if "severity" in rule and rule.get("severity") not in ALLOWED_SEVERITIES:
        errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Invalid 'severity' value '{rule.get('severity')}'. Allowed: {ALLOWED_SEVERITIES}")
    if "action_on_match" in rule and rule.get("action_on_match") not in ALLOWED_ACTIONS:
        errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Invalid 'action_on_match' value '{rule.get('action_on_match')}'. Allowed: {ALLOWED_ACTIONS}")
    
    if 'enabled' in rule and isinstance(rule['enabled'], str) and rule['enabled'].lower() not in ['true', 'false']:
        errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Key 'enabled' has incorrect string value. Expected 'true' or 'false', got '{rule['enabled']}'.")
    return errors

def load_rules_from_yaml(filepath: str) -> List[Dict[str, Any]]:
    """
    Loads rules from a YAML file and performs basic structural validation.
    """
    # Log the absolute path being attempted (as per feedback document)
    abs_filepath = os.path.abspath(filepath)
    print(f"[QueryGuard Rule Loader] Attempting to load YAML rules from absolute path: {abs_filepath}")

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            rules_data_wrapper = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[QueryGuard Rule Loader] Error: Rule file not found at '{filepath}' (resolved to '{abs_filepath}').")
        raise
    except yaml.YAMLError as e:
        print(f"[QueryGuard Rule Loader] Error parsing YAML rule file '{abs_filepath}': {e}")
        raise
    except Exception as e:
        print(f"[QueryGuard Rule Loader] An unexpected error occurred for '{abs_filepath}': {e}")
        raise ValueError(f"Unexpected error during file/YAML processing for '{abs_filepath}': {e}")

    if not isinstance(rules_data_wrapper, dict) or EXPECTED_TOP_LEVEL_KEY not in rules_data_wrapper:
        msg = f"[QueryGuard Rule Loader] Error: YAML content in '{abs_filepath}' must be a dictionary with a top-level '{EXPECTED_TOP_LEVEL_KEY}' key."
        print(msg)
        raise ValueError(msg)
    
    ruleset_from_yaml = rules_data_wrapper.get(EXPECTED_TOP_LEVEL_KEY, [])
    if not isinstance(ruleset_from_yaml, list):
        msg = f"[QueryGuard Rule Loader] Error: The '{EXPECTED_TOP_LEVEL_KEY}' key in '{abs_filepath}' must contain a list of rules."
        print(msg)
        raise ValueError(msg)
        
    validated_ruleset = []
    all_errors = []
    for i, rule_dict in enumerate(ruleset_from_yaml):
        if not isinstance(rule_dict, dict):
            all_errors.append(f"Rule {i+1} in '{abs_filepath}' is not a dictionary.")
            continue
        
        if 'enabled' in rule_dict and isinstance(rule_dict['enabled'], str):
            if rule_dict['enabled'].lower() == 'true':
                rule_dict['enabled'] = True
            elif rule_dict['enabled'].lower() == 'false':
                rule_dict['enabled'] = False
        
        validation_errors = _validate_rule(rule_dict, i)
        if validation_errors:
            # Prepend file information to each error for clarity
            for err_idx, err_msg in enumerate(validation_errors):
                validation_errors[err_idx] = f"In file '{abs_filepath}', {err_msg}"
            all_errors.extend(validation_errors)
        else:
            if 'enabled' not in rule_dict:
                rule_dict['enabled'] = True
            elif not isinstance(rule_dict['enabled'], bool):
                 all_errors.append(f"In file '{abs_filepath}', Rule {i+1} (ID: {rule_dict.get('rule_id', 'N/A')}): 'enabled' is not a boolean after processing.")
            
            if not all_errors or not any(f"Rule {i+1}" in e for e in all_errors): # Add rule if it had no new errors
                 validated_ruleset.append(rule_dict)

    if all_errors:
        error_summary = "\n".join(sorted(list(set(all_errors))))
        msg = f"[QueryGuard Rule Loader] Validation failed for rule file '{abs_filepath}' with {len(set(all_errors))} unique error(s):\n{error_summary}"
        print(msg)
        raise ValueError(msg)
            
    print(f"[QueryGuard Rule Loader] Successfully loaded and validated {len(validated_ruleset)} rules from '{abs_filepath}'.")
    return validated_ruleset

if __name__ == '__main__':
    # (The __main__ block for testing remains the same as before)
    # Create a dummy valid YAML file for testing
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
    description: "Another valid test rule, enabled by default."
    severity: "LOW"
    detection_logic:
      check_function: "some_other_check"
    action_on_match: "ALLOW"
    message_template: "Test rule 002 triggered."
  - rule_id: "TEST-003"
    rule_name: "Test Rule String Enabled"
    description: "Rule with 'enabled' as string."
    enabled: "false" 
    severity: "INFO"
    detection_logic:
      check_function: "some_check"
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
    enabled: true
    detection_logic:
      parameters: {}
    action_on_match: "BLOCK"
    message_template: "Invalid rule 001 triggered."
  - rule_id: "INVALID-002"
    rule_name: "Invalid Rule Two"
    description: "Another invalid rule."
    enabled: "yes" 
    severity: "VERY_HIGH" 
    detection_logic:
      check_function: 123 
    action_on_match: "DESTROY" 
    message_template: "Invalid rule 002 triggered."
"""
    invalid_yaml_path = "temp_invalid_rules.yaml"
    with open(invalid_yaml_path, "w", encoding="utf-8") as f:
        f.write(dummy_invalid_rules_content)

    print("\n--- Testing rule_loader with VALID file ---")
    try:
        loaded_rules = load_rules_from_yaml(valid_yaml_path)
        for r_idx, r_val in enumerate(loaded_rules):
            print(f"  Loaded Rule {r_idx+1}: ID={r_val.get('rule_id')}, Enabled={r_val.get('enabled')}, Type={type(r_val.get('enabled'))}")
    except Exception as e:
        print(f"  Test FAILED for valid file: {e}")

    print("\n--- Testing rule_loader with INVALID file ---")
    try:
        loaded_rules = load_rules_from_yaml(invalid_yaml_path)
        print(f"  Loaded {len(loaded_rules)} rules (should have failed or loaded 0).")
    except ValueError as e:
        print(f"  Test PASSED (as expected) with ValueError. Errors:\n    {str(e).replace(chr(10), chr(10) + '    ')}")
    except Exception as e:
        print(f"  Test FAILED for invalid file with unexpected error: {e}")

    print("\n--- Testing rule_loader with NONEXISTENT file ---")
    try:
        load_rules_from_yaml("nonexistent_rules.yaml")
    except FileNotFoundError:
        print("  Test PASSED (as expected) with FileNotFoundError.")
    except Exception as e:
        print(f"  Test FAILED for non-existent file with unexpected error: {e}")

    if os.path.exists(valid_yaml_path): os.remove(valid_yaml_path)
    if os.path.exists(invalid_yaml_path): os.remove(invalid_yaml_path)
