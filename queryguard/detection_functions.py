# queryguard/detection_functions.py

"""
Collection of specific detection functions for QueryGuard.
These functions will be called by the core evaluation logic based on rule configurations.
"""
from typing import Dict, List, Any, Optional
import re # For regex-based detections
# Consider adding libraries for fuzzy matching, unicode normalization if not in utils

# from .utils import normalize_text # Example: if NFKC normalization is a util

def detect_unicode_evasion(text: str, high_risk_ranges: Optional[List[str]] = None, homoglyph_map: Optional[Dict[str, str]] = None) -> List[str]:
    """
    Detects Unicode-based evasion techniques.
   
    """
    findings = []
    # TODO: Implement NFKC normalization (perhaps in utils or here)
    # normalized_text = normalize_text(text, "NFKC")
    normalized_text = text # Placeholder

    # Example: Check for high-risk Unicode ranges
    if high_risk_ranges:
        for r_start, r_end in high_risk_ranges: # Assuming ranges are tuples of ordinals
            for char_code in range(r_start, r_end + 1):
                if chr(char_code) in normalized_text:
                    findings.append(f"INVISIBLE_CHAR_U+{char_code:04X}")
                    # For performance, might break after first find or collect all
    
    # TODO: Implement homoglyph detection using homoglyph_map
    if homoglyph_map:
        for keyword, mapped_chars in homoglyph_map.items():
            # This is a simplified concept; robust homoglyph detection is complex
            pass

    print(f"[Detection] Unicode Evasion Check on '{text[:30]}...': Found {findings}")
    return findings

def detect_structural_manipulation(text: str) -> Dict[str, bool]:
    """
    Detects "Policy Puppetry" or deeply embedded instructions.
   
    """
    results = {"policy_puppetry_detected": False, "buried_instruction_suspected": False}
    
    # Basic regex for YAML/JSON-like structures with instruction keywords
    # This is a simplified example
    policy_pattern = r"(\{|\"|\'|config:|policy:).*?(ignore|override|task|instruction|goal).*?(\}|\"|\')"
    if re.search(policy_pattern, text, re.IGNORECASE | re.DOTALL):
        results["policy_puppetry_detected"] = True
        
    # TODO: Add logic for buried instructions (more complex)
    print(f"[Detection] Structural Manipulation Check on '{text[:30]}...': {results}")
    return results

def analyze_text_statistics(text: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Analyzes text for statistical anomalies (entropy, char distribution, repetition).
   
    """
    if config is None:
        config = {}
    results = {"metrics": {}, "anomalies_triggered": []}
    
    # TODO: Implement character entropy calculation
    # TODO: Implement character type distribution (alphanum, symbol, non-Latin etc.)
    # TODO: Implement excessive repetition check (e.g., QG-008)
    
    # Example: Length check (can be a simple stat)
    max_len = config.get("max_length", 2000)
    if len(text) > max_len:
        results["anomalies_triggered"].append("EXCESSIVE_LENGTH")
    results["metrics"]["length"] = len(text)

    print(f"[Detection] Text Statistics Check on '{text[:30]}...': {results}")
    return results

def detect_suspicious_ngrams(text: str, suspicious_ngram_sets: Dict[str, List[str]], threshold: int = 1) -> List[str]:
    """
    Detects suspicious N-grams (word or character).
   
    """
    # For simplicity, let's assume word n-grams and text is already tokenized (e.g. by space)
    words = text.lower().split()
    matched_categories = []

    for category, ngrams in suspicious_ngram_sets.items():
        count = 0
        for ngram_phrase in ngrams:
            ngram_words = ngram_phrase.lower().split()
            n = len(ngram_words)
            if n == 0: continue
            
            for i in range(len(words) - n + 1):
                if words[i:i+n] == ngram_words:
                    count += 1
        if count >= threshold:
            matched_categories.append(category)
            
    print(f"[Detection] N-gram Check on '{text[:30]}...': Found categories {matched_categories}")
    return matched_categories

def detect_common_encodings(text: str) -> List[Dict[str, Any]]:
    """
    Detects common encoding patterns like Base64, Hex, URL.
   
    """
    findings = []
    # Regex for Base64: often long strings of A-Za-z0-9+/=, often with padding ==
    # Min length for payload, e.g., 20 chars encoded
    base64_pattern = r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    # Regex for Hex: often long strings of 0-9a-fA-F
    hex_pattern = r'(?:[0-9a-fA-F]{2}){10,}' # Min 10 bytes
    # Regex for URL encoding: % followed by two hex chars
    url_enc_pattern = r'(?:%[0-9a-fA-F]{2}){5,}' # Min 5 encoded chars

    for match in re.finditer(base64_pattern, text):
        findings.append({"type": "BASE64_SUSPECTED", "span": match.span(), "value": match.group(0)[:30]+"..."})
    for match in re.finditer(hex_pattern, text):
        findings.append({"type": "HEX_SUSPECTED", "span": match.span(), "value": match.group(0)[:30]+"..."})
    for match in re.finditer(url_enc_pattern, text):
         findings.append({"type": "URL_ENCODING_SUSPECTED", "span": match.span(), "value": match.group(0)[:30]+"..."})
    
    if findings:
        print(f"[Detection] Encoding Check on '{text[:30]}...': Found {findings}")
    return findings

def detect_direct_injection_variants(text: str, injection_phrases: List[str], fuzzy_threshold: float = 0.85) -> bool:
    """
    Detects direct prompt injection phrases with fuzzy matching.
   
    """
    # TODO: Implement fuzzy matching (e.g., using a library like thefuzz)
    # For now, simple case-insensitive exact phrase matching for concept
    text_lower = text.lower()
    for phrase in injection_phrases:
        if phrase.lower() in text_lower: # Replace with fuzzy match
            print(f"[Detection] Direct Injection Check on '{text[:30]}...': Found '{phrase}'")
            return True
    return False