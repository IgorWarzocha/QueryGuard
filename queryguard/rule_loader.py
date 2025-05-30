# queryguard/rule_loader.py

"""
Handles loading and validation of QueryGuard rule configuration files.
"""
import yaml
from typing import List, Dict, Any

# Could define a TypedDict or Pydantic model for Rule for validation later

def load_rules_from_yaml(filepath: str) -> List[Dict[str, Any]]:
    """
    Loads rules from a YAML file.

    Args:
        filepath (str): The path to the YAML rule file.

    Returns:
        List[Dict[str, Any]]: A list of rule dictionaries.
                               Returns an empty list if file not found or error.
    
    Raises:
        yaml.YAMLError: If there's an issue parsing the YAML.
        FileNotFoundError: If the filepath does not exist.
    """
    print(f"[Rule Loader] Attempting to load rules from: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            rules_data = yaml.safe_load(f)
        
        if not isinstance(rules_data, dict) or "rules" not in rules_data:
            print("[Rule Loader] Error: YAML content must be a dictionary with a 'rules' key.")
            return []
        
        ruleset = rules_data.get("rules", [])
        if not isinstance(ruleset, list):
            print("[Rule Loader] Error: The 'rules' key must contain a list of rules.")
            return []
            
        # TODO: Add validation for each rule's structure against the defined schema
        # (e.g., presence of rule_id, severity, detection_logic, etc.)
        # For now, we assume rules are correctly structured.
        
        print(f"[Rule Loader] Successfully loaded {len(ruleset)} rules.")
        return ruleset
    except FileNotFoundError:
        print(f"[Rule Loader] Error: Rule file not found at {filepath}")
        raise
    except yaml.YAMLError as e:
        print(f"[Rule Loader] Error parsing YAML rule file {filepath}: {e}")
        raise
    except Exception as e:
        print(f"[Rule Loader] An unexpected error occurred while loading rules: {e}")
        return [] # Or re-raise