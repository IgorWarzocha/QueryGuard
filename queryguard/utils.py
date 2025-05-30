# queryguard/utils.py

"""
Utility functions for QueryGuard.
"""

# Example: A text normalization function (could be expanded)
def normalize_text(text: str, method: str = "NFKC") -> str:
    """
    Normalizes text using specified Unicode normalization form.
    Requires a library like 'unicodedata2' or similar if Python's unicodedata
    doesn't suffice for all desired normalizations, or for older Pythons.
    """
    import unicodedata
    if method == "NFKC":
        return unicodedata.normalize('NFKC', text)
    elif method == "NFC":
        return unicodedata.normalize('NFC', text)
    # Add other methods as needed
    return text

# Placeholder for other utilities
# e.g., fuzzy_match_score(string1, string2, algorithm="levenshtein")