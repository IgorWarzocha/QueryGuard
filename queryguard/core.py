# queryguard/core.py

"""
Core evaluation logic for QueryGuard.
"""

from typing import Dict, List, Tuple, Any, Optional

# We'll import rule_loader and detection_functions later
# from .rule_loader import Rule
# from . import detection_functions
# from .utils import normalize_text # Assuming a normalization function

def evaluate_input_advanced(
    user_input: str,
    ruleset: List[Dict[str, Any]], # Represents loaded rules
    session_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates user input against a defined ruleset using advanced checks.

    Args:
        user_input (str): The input string from the user.
        ruleset (List[Dict[str, Any]]): A list of rule dictionaries,
                                         loaded and validated.
        session_context (Optional[Dict[str, Any]]): Optional dictionary
                                                    containing session-specific
                                                    context (e.g., user trust level).

    Returns:
        Dict[str, Any]: A dictionary containing the evaluation results, e.g.,
                        {
                            "final_action": "ALLOW" | "BLOCK" | "FLAG" | "REQUEST_REPHRASE",
                            "triggered_rules": [
                                {
                                    "rule_id": str,
                                    "rule_name": str,
                                    "severity": str,
                                    "message": str
                                }
                            ],
                            "risk_score": Optional[float],
                            "processed_input": str # Potentially normalized input
                        }
    """
    print(f"[QueryGuard Core] Evaluating input: '{user_input[:50]}...'") # Dev log

    # 1. (Optional) Global Pre-processing (e.g., Unicode normalization)
    #    Example: processed_input = normalize_text(user_input, method="NFKC")
    processed_input = user_input # Placeholder

    triggered_rules_details = []
    cumulative_risk_score = 0.0
    final_action = "ALLOW" # Default action

    # 2. Staged Rule Execution (conceptual - needs refinement based on rule properties)
    #    For now, iterate directly. We can sort rules by priority/cost later.
    for rule in ruleset:
        if not rule.get("enabled", True):
            continue

        detection_function_name = rule.get("detection_logic", {}).get("check_function")
        parameters = rule.get("detection_logic", {}).get("parameters", {})

        # Dynamically call detection functions (this will require more robust handling)
        # For now, this is a conceptual placeholder.
        # detection_func = getattr(detection_functions, detection_function_name, None)
        detection_func = None # Placeholder

        if detection_func:
            try:
                # Pass necessary context and parameters
                # This needs to map parameters from rule to function arguments
                # Example: result = detection_func(processed_input, **parameters)
                # For now, let's assume a simple boolean result for concept
                # In reality, functions might return more detailed findings or lists

                # --- Placeholder for dynamic function call ---
                # This is where specific function calls like:
                # if detection_function_name == "detect_unicode_evasion":
                #   findings = detection_functions.detect_unicode_evasion(processed_input, **parameters)
                #   if findings: is_triggered = True else: is_triggered = False
                # For this skeleton, let's simulate a trigger for specific rule_id for demo
                is_triggered = False
                if rule.get("rule_id") == "QG-U001" and "U+E0049" in processed_input: # Example simulation
                    is_triggered = True
                # --- End Placeholder ---

                if is_triggered:
                    print(f"[QueryGuard Core] Rule '{rule.get('rule_id')}' triggered.")
                    triggered_rules_details.append({
                        "rule_id": rule.get("rule_id"),
                        "rule_name": rule.get("rule_name"),
                        "severity": rule.get("severity"),
                        "message": rule.get("message_template", "Threat detected.")
                    })
                    # Basic action determination (can be more complex with risk scores)
                    # For now, highest severity of triggered rule dictates action if multiple trigger
                    # Or first BLOCK action.
                    current_action = rule.get("action_on_match", "FLAG")
                    if final_action != "BLOCK": # Prioritize BLOCK
                        if current_action == "BLOCK":
                            final_action = "BLOCK"
                        elif current_action == "REQUEST_REPHRASE" and final_action == "ALLOW":
                            final_action = "REQUEST_REPHRASE"
                        elif current_action == "FLAG" and final_action == "ALLOW":
                            final_action = "FLAG"
                    
                    # Placeholder for risk score accumulation
                    # cumulative_risk_score += rule.get("confidence_score_factor", 0.0)

                    if final_action == "BLOCK": # If a block action is triggered, can stop early
                        break 
            except Exception as e:
                print(f"[QueryGuard Core] Error executing rule {rule.get('rule_id')}: {e}")
                # Potentially log this or handle specific exceptions

        else:
            print(f"[QueryGuard Core] Warning: Detection function '{detection_function_name}' not found for rule '{rule.get('rule_id')}'.")


    # Determine final action based on triggered rules and risk score (simplified here)
    if not triggered_rules_details and final_action == "ALLOW":
        print("[QueryGuard Core] No rules triggered. Input allowed.")
    
    # More sophisticated logic for final_action based on risk_score can be added here.
    # For instance, if cumulative_risk_score > some_threshold: final_action = "BLOCK"

    return {
        "final_action": final_action,
        "triggered_rules": triggered_rules_details,
        "risk_score": cumulative_risk_score if triggered_rules_details else 0.0,
        "processed_input": processed_input
    }