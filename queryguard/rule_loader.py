# queryguard/rule_loader.py

"""
Handles loading and basic validation of QueryGuard rule configuration files.
"""
import yaml
from typing import List, Dict, Any, Union

# Define expected top-level keys and essential rule keys for validation
# This could be expanded into a more formal schema later
EXPECTED_TOP_LEVEL_KEY = "rules"
ESSENTIAL_RULE_KEYS = {
    "rule_id": str,
    "enabled": bool, # Though optional in definition, good to check if present
    "severity": str,
    "detection_logic": dict,
    "action_on_match": str,
    "rule_name": str, # Added as essential for clarity
    "description": str, # Added as essential
    "message_template": str, # Added as essential
}
ESSENTIAL_DETECTION_LOGIC_KEYS = {
    "check_function": str,
    # "parameters" is optional, so not listed as strictly essential here for all rules
}

# Define allowed values for certain keys (examples)
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
            # Special handling for 'enabled' if it comes from YAML as string 'true'/'false'
            if key == 'enabled' and isinstance(rule[key], str) and rule[key].lower() in ['true', 'false']:
                pass # Will be converted later, or handle conversion here
            else:
                errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Key '{key}' has incorrect type. Expected {expected_type.__name__}, got {type(rule[key]).__name__}.")


    detection_logic = rule.get("detection_logic")
    if isinstance(detection_logic, dict):
        for key, expected_type in ESSENTIAL_DETECTION_LOGIC_KEYS.items():
            if key not in detection_logic:
                errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Missing key '{key}' in 'detection_logic'.")
            elif not isinstance(detection_logic[key], expected_type):
                 errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Key '{key}' in 'detection_logic' has incorrect type. Expected {expected_type.__name__}, got {type(detection_logic[key]).__name__}.")
    # No 'else' needed here as the case where detection_logic is not a dict or missing
    # would ideally be caught by the ESSENTIAL_RULE_KEYS check if "detection_logic" itself is wrong type/missing.


    if "severity" in rule and rule.get("severity") not in ALLOWED_SEVERITIES:
        errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Invalid 'severity' value '{rule.get('severity')}'. Allowed: {ALLOWED_SEVERITIES}")
    if "action_on_match" in rule and rule.get("action_on_match") not in ALLOWED_ACTIONS:
        errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Invalid 'action_on_match' value '{rule.get('action_on_match')}'. Allowed: {ALLOWED_ACTIONS}")
        
    # 'enabled' will be defaulted to True later if missing.
    # If present and not a boolean (and not 'true'/'false' string), it would be caught by type check.
    if 'enabled' in rule and isinstance(rule['enabled'], str) and rule['enabled'].lower() not in ['true', 'false']:
        errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Key 'enabled' has incorrect string value. Expected 'true' or 'false', got '{rule['enabled']}'.")


    return errors


def load_rules_from_yaml(filepath: str) -> List[Dict[str, Any]]:
    """
    Loads rules from a YAML file and performs basic structural validation.

    Args:
        filepath (str): The path to the YAML rule file.

    Returns:
        List[Dict[str, Any]]: A list of validated rule dictionaries.
    
    Raises:
        FileNotFoundError: If the filepath does not exist.
        yaml.YAMLError: If there's an issue parsing the YAML.
        ValueError: If rule validation fails or critical structure is missing.
    """
    print(f"[Rule Loader] Attempting to load rules from: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            rules_data_wrapper = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[Rule Loader] Error: Rule file not found at {filepath}")
        raise
    except yaml.YAMLError as e:
        print(f"[Rule Loader] Error parsing YAML rule file {filepath}: {e}")
        raise
    except Exception as e:
        print(f"[Rule Loader] An unexpected error occurred during file reading or YAML parsing: {e}")
        raise ValueError(f"Unexpected error during file/YAML processing: {e}")


    if not isinstance(rules_data_wrapper, dict) or EXPECTED_TOP_LEVEL_KEY not in rules_data_wrapper:
        msg = f"[Rule Loader] Error: YAML content must be a dictionary with a top-level '{EXPECTED_TOP_LEVEL_KEY}' key."
        print(msg)
        raise ValueError(msg)
    
    ruleset_from_yaml = rules_data_wrapper.get(EXPECTED_TOP_LEVEL_KEY, [])
    if not isinstance(ruleset_from_yaml, list):
        msg = f"[Rule Loader] Error: The '{EXPECTED_TOP_LEVEL_KEY}' key must contain a list of rules."
        print(msg)
        raise ValueError(msg)
        
    validated_ruleset = []
    all_errors = []
    for i, rule_dict in enumerate(ruleset_from_yaml):
        if not isinstance(rule_dict, dict):
            all_errors.append(f"Rule {i+1} is not a dictionary.")
            continue
        
        # Handle string 'true'/'false' for 'enabled' before validation
        if 'enabled' in rule_dict and isinstance(rule_dict['enabled'], str):
            if rule_dict['enabled'].lower() == 'true':
                rule_dict['enabled'] = True
            elif rule_dict['enabled'].lower() == 'false':
                rule_dict['enabled'] = False
            # If still a string here, _validate_rule will catch it as wrong type or value.

        validation_errors = _validate_rule(rule_dict, i)
        if validation_errors:
            all_errors.extend(validation_errors)
        else:
            # Ensure 'enabled' field exists, defaulting to True if not specified and valid type.
            if 'enabled' not in rule_dict:
                rule_dict['enabled'] = True
            elif not isinstance(rule_dict['enabled'], bool):
                 # This case should ideally be caught by _validate_rule if it was an invalid string.
                 # If it was some other non-bool type, _validate_rule already caught it.
                 # For safety, ensuring it's bool after all checks.
                 all_errors.append(f"Rule {i+1} (ID: {rule_dict.get('rule_id', 'N/A')}): 'enabled' is not a boolean after processing.")


            if not validation_errors: # Add to set if still no errors for this rule
                validated_ruleset.append(rule_dict)

    if all_errors:
        error_summary = "\n".join(sorted(list(set(all_errors)))) # Show unique errors
        msg = f"[Rule Loader] Validation failed for rule file {filepath} with {len(all_errors)} error(s):\n{error_summary}"
        print(msg)
        raise ValueError(msg)
            
    print(f"[Rule Loader] Successfully loaded and validated {len(validated_ruleset)} rules from {filepath}.")
    return validated_ruleset


if __name__ == '__main__':
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
    # Missing 'severity'
    enabled: true
    detection_logic:
      # Missing 'check_function'
      parameters: {}
    action_on_match: "BLOCK"
    message_template: "Invalid rule 001 triggered."
  - rule_id: "INVALID-002"
    rule_name: "Invalid Rule Two"
    description: "Another invalid rule."
    enabled: "yes" # Not 'true' or 'false'
    severity: "VERY_HIGH" # Not in allowed list
    detection_logic:
      check_function: 123 # Not a string
    action_on_match: "DESTROY" # Not in allowed list
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

    # Clean up dummy files
    import os
    if os.path.exists(valid_yaml_path): os.remove(valid_yaml_path)
    if os.path.exists(invalid_yaml_path): os.remove(invalid_yaml_path)
