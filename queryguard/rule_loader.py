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
            errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Key '{key}' has incorrect type. Expected {expected_type.__name__}, got {type(rule[key]).__name__}.")

    # Validate detection_logic structure
    detection_logic = rule.get("detection_logic")
    if isinstance(detection_logic, dict):
        for key, expected_type in ESSENTIAL_DETECTION_LOGIC_KEYS.items():
            if key not in detection_logic:
                errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Missing key '{key}' in 'detection_logic'.")
            elif not isinstance(detection_logic[key], expected_type):
                 errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Key '{key}' in 'detection_logic' has incorrect type. Expected {expected_type.__name__}, got {type(detection_logic[key]).__name__}.")
    else:
        # This was already caught by ESSENTIAL_RULE_KEYS if detection_logic itself was missing or wrong type
        pass

    # Validate severity and action values
    if "severity" in rule and rule["severity"] not in ALLOWED_SEVERITIES:
        errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Invalid 'severity' value '{rule['severity']}'. Allowed: {ALLOWED_SEVERITIES}")
    if "action_on_match" in rule and rule["action_on_match"] not in ALLOWED_ACTIONS:
        errors.append(f"Rule {rule_index+1} (ID: {rule.get('rule_id', 'N/A')}): Invalid 'action_on_match' value '{rule['action_on_match']}'. Allowed: {ALLOWED_ACTIONS}")
        
    # Optional: Check for 'enabled' explicitly if rules should always have it
    if "enabled" not in rule: # If we decide 'enabled' is not optional
        rule["enabled"] = True # Default to true if missing, or raise error

    return errors


def load_rules_from_yaml(filepath: str) -> List[Dict[str, Any]]:
    """
    Loads rules from a YAML file and performs basic structural validation.

    Args:
        filepath (str): The path to the YAML rule file.

    Returns:
        List[Dict[str, Any]]: A list of validated rule dictionaries.
                               Returns an empty list if file not found,
                               parsing error, or structural validation fails.
    
    Raises:
        FileNotFoundError: If the filepath does not exist.
        yaml.YAMLError: If there's an issue parsing the YAML.
        ValueError: If rule validation fails.
    """
    print(f"[Rule Loader] Attempting to load rules from: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Use FullLoader or SafeLoader. SafeLoader is generally recommended.
            rules_data_wrapper = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[Rule Loader] Error: Rule file not found at {filepath}")
        raise
    except yaml.YAMLError as e:
        print(f"[Rule Loader] Error parsing YAML rule file {filepath}: {e}")
        raise
    except Exception as e:
        print(f"[Rule Loader] An unexpected error occurred during file reading or YAML parsing: {e}")
        # Depending on policy, could return empty list or re-raise
        raise ValueError(f"Unexpected error during file/YAML processing: {e}")


    if not isinstance(rules_data_wrapper, dict) or EXPECTED_TOP_LEVEL_KEY not in rules_data_wrapper:
        msg = f"[Rule Loader] Error: YAML content must be a dictionary with a top-level '{EXPECTED_TOP_LEVEL_KEY}' key."
        print(msg)
        raise ValueError(msg)
    
    ruleset = rules_data_wrapper.get(EXPECTED_TOP_LEVEL_KEY, [])
    if not isinstance(ruleset, list):
        msg = f"[Rule Loader] Error: The '{EXPECTED_TOP_LEVEL_KEY}' key must contain a list of rules."
        print(msg)
        raise ValueError(msg)
        
    validated_ruleset = []
    all_errors = []
    for i, rule_dict in enumerate(ruleset):
        if not isinstance(rule_dict, dict):
            all_errors.append(f"Rule {i+1} is not a dictionary.")
            continue
        
        validation_errors = _validate_rule(rule_dict, i)
        if validation_errors:
            all_errors.extend(validation_errors)
        else:
            # Ensure 'enabled' field exists, defaulting to True if not specified.
            # This simplifies logic in the core engine.
            if 'enabled' not in rule_dict:
                rule_dict['enabled'] = True
            validated_ruleset.append(rule_dict)

    if all_errors:
        error_summary = "\n".join(all_errors)
        msg = f"[Rule Loader] Validation failed for rule file {filepath}:\n{error_summary}"
        print(msg)
        # Decide if to return partially valid rules or raise an error for any invalid rule
        # For now, let's be strict: if any rule is invalid, the whole set is problematic.
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
    # 'enabled' key is missing, should default to true
    severity: "LOW"
    detection_logic:
      check_function: "some_other_check"
    action_on_match: "ALLOW" # Not a typical action for a triggered rule, but valid
    message_template: "Test rule 002 triggered."
"""
    valid_yaml_path = "temp_valid_rules.yaml"
    with open(valid_yaml_path, "w", encoding="utf-8") as f:
        f.write(dummy_valid_rules_content)

    # Create a dummy invalid YAML file
    dummy_invalid_rules_content = """
rules:
  - rule_id: "INVALID-001"
    # Missing 'severity'
    enabled: true
    detection_logic:
      # Missing 'check_function'
      parameters: {}
    action_on_match: "BLOCK"
    rule_name: "Invalid Rule One"
    description: "An invalid rule."
    message_template: "Invalid rule 001 triggered."
  - rule_id: "INVALID-002"
    rule_name: "Invalid Rule Two"
    description: "Another invalid rule."
    enabled: "yes" # Not a boolean
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
        for r in loaded_rules:
            print(f"  Loaded Rule: {r.get('rule_id')}, Enabled: {r.get('enabled')}")
    except Exception as e:
        print(f"  Test FAILED: {e}")

    print("\n--- Testing rule_loader with INVALID file ---")
    try:
        loaded_rules = load_rules_from_yaml(invalid_yaml_path)
        print(f"  Loaded {len(loaded_rules)} rules (should have failed or loaded 0).")
    except ValueError as e:
        print(f"  Test PASSED (as expected) with ValueError:\n    {str(e).replacechr(10), '    n')}") # Indent error for readability
    except Exception as e:
        print(f"  Test FAILED with unexpected error: {e}")

    print("\n--- Testing rule_loader with NONEXISTENT file ---")
    try:
        loaded_rules = load_rules_from_yaml("nonexistent_rules.yaml")
    except FileNotFoundError:
        print("  Test PASSED (as expected) with FileNotFoundError.")
    except Exception as e:
        print(f"  Test FAILED with unexpected error: {e}")

    # Clean up dummy files
    import os
    os.remove(valid_yaml_path)
    os.remove(invalid_yaml_path)
