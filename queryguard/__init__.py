# queryguard/__init__.py

"""
QueryGuard: A pre-LLM input filtering and validation library.

This library provides tools to detect and mitigate common and advanced abuse patterns,
instruction injections, data exfiltration attempts, and resource exhaustion strategies
before a query is sent to a primary Large Language Model (LLM).

Designed to be lightweight, fast, and highly configurable through external YAML rule files.
"""

# Import key functions/classes to make them available at the package level
# e.g., from queryguard import evaluate_input_advanced, load_rules_from_yaml

from .core import evaluate_input_advanced
from .rule_loader import load_rules_from_yaml
# Potentially import specific detection functions if they are meant to be directly usable
# or if users might want to call them independently for specific checks.
# For now, they are primarily used by the core engine via rule configuration.

# Import utility functions if they are part of the public API
# from .utils import normalize_text # Example, if needed publicly

__version__ = "0.1.0"  # Updated to a more standard initial dev version

# Define what gets imported with 'from queryguard import *'
# It's good practice to define __all__ if you use 'import *',
# though direct imports are generally preferred for clarity.
__all__ = [
    'evaluate_input_advanced',
    'load_rules_from_yaml',
    '__version__'
    # Add other public API elements here if any
]

# Optional: A log message to confirm package initialization during development
# print(f"QueryGuard package (version {__version__}) initialized.")
