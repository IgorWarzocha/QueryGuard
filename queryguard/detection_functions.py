# queryguard/detection_functions.py

"""
Collection of specific detection functions for QueryGuard.
These functions will be called by the core evaluation logic based on rule configurations.
"""
import re
from typing import Dict, List, Any, Optional, Tuple

# Import utilities from the same package
from .utils import normalize_text, calculate_shannon_entropy, get_character_type_distribution

# Import fuzzy matching library (ensure it's in requirements.txt)
from fuzzywuzzy import fuzz

# --- Unicode Evasion Detection ---
def detect_unicode_evasion(
    text: str,
    high_risk_ranges: Optional[List[Tuple[int, int]]] = None,
    critical_keywords_homoglyph_map: Optional[Dict[str, List[str]]] = None,
    normalization_form: str = 'NFKC'
) -> List[str]:
    """
    Detects Unicode-based evasion techniques like invisible characters and homoglyphs
    for critical keywords.
   

    Args:
        text (str): The input text to analyze.
        high_risk_ranges (Optional[List[Tuple[int, int]]]): A list of tuples,
            each defining a start and end ordinal for a Unicode range considered high-risk.
        critical_keywords_homoglyph_map (Optional[Dict[str, List[str]]]):
            A dictionary where keys are canonical critical keywords (e.g., "password")
            and values are lists of known homoglyph-obfuscated versions of that keyword.
        normalization_form (str): The Unicode normalization form to apply first.

    Returns:
        List[str]: A list of strings describing detected evasion techniques.
                   Examples: ["INVISIBLE_CHAR_U+200B", "HOMOGLYPH_FOR_PASSWORD"]
    """
    findings = []
    if not text:
        return findings

    normalized_text = normalize_text(text, form=normalization_form)

    # 1. Check for high-risk Unicode characters (invisible, control, tags, etc.)
    if high_risk_ranges:
        for char_ord in map(ord, normalized_text): # More efficient for checking ordinals
            for r_start, r_end in high_risk_ranges:
                if r_start <= char_ord <= r_end:
                    finding_str = f"HIGH_RISK_UNICODE_CHAR_U+{char_ord:04X}"
                    if finding_str not in findings: # Avoid duplicate messages for same char type
                         findings.append(finding_str)
                    # Potentially break from inner loop if one char can only be in one range
                    # but for overlapping ranges, this captures all.

    # 2. Check for homoglyph-obfuscated critical keywords
    if critical_keywords_homoglyph_map:
        # This is a basic check. More sophisticated homoglyph detection might involve
        # character-by-character comparison against a full homoglyph map for each char in keywords.
        # For pre-filter, using a pre-compiled list of known obfuscated keywords is more performant.
        text_lower_for_homoglyph_check = normalized_text.lower() # Or use original text if map handles cases
        for canonical_keyword, obfuscated_versions in critical_keywords_homoglyph_map.items():
            for obfuscated_variant in obfuscated_versions:
                if obfuscated_variant in text_lower_for_homoglyph_check: # Simple substring check
                    finding_str = f"HOMOGLYPH_SUSPECTED_FOR_{canonical_keyword.upper()}"
                    if finding_str not in findings:
                        findings.append(finding_str)
                    break # Found one variant for this canonical keyword

    if findings:
        print(f"[Detection] Unicode Evasion Check on '{text[:30]}...': Found {findings}")
    return findings

# --- Structural Manipulation Detection ---
def detect_structural_manipulation(
    text: str,
    policy_structure_patterns: Optional[List[str]] = None, # List of regex patterns for structures
    instruction_keywords: Optional[List[str]] = None # Keywords to find within those structures
) -> Dict[str, bool]:
    """
    Detects "Policy Puppetry" (e.g., YAML/JSON/XML-like structures with override keywords)
    and attempts to find instructions deeply embedded in text.
   

    Args:
        text (str): The input text.
        policy_structure_patterns (Optional[List[str]]): Regex patterns that identify
            policy-like structures.
        instruction_keywords (Optional[List[str]]): Keywords indicating instruction override
            if found within or near detected structures.

    Returns:
        Dict[str, bool]: {"policy_puppetry_detected": bool, "buried_instruction_suspected": bool}
    """
    results = {"policy_puppetry_detected": False, "buried_instruction_suspected": False}
    if not text:
        return results

    text_lower = text.lower() # For case-insensitive keyword matching

    # 1. Policy Puppetry Detection
    if policy_structure_patterns and instruction_keywords:
        for struct_pattern in policy_structure_patterns:
            try:
                # Find all occurrences of the structure
                for match in re.finditer(struct_pattern, text, re.IGNORECASE | re.DOTALL):
