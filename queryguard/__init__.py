# queryguard/__init__.py

"""
QueryGuard: A pre-LLM input filtering and validation library.

This library provides tools to detect and mitigate common and advanced abuse patterns,
instruction injections, data exfiltration attempts, and resource exhaustion strategies
before a query is sent to a primary Large Language Model (LLM).

Designed to be lightweight, fast, and highly configurable through external YAML rule files.
"""

import logging
from typing import Optional # Import Optional for type hinting

# Import key functions/classes to make them available at the package level
from .core import evaluate_input_advanced
from .rule_loader import load_rules_from_yaml

__version__ = "0.1.1" # Assuming a patch version bump for the fix

# Define what gets imported with 'from queryguard import *'
__all__ = [
    'evaluate_input_advanced',
    'load_rules_from_yaml',
    'setup_logging',
    '__version__'
]

# Set up a logger for the QueryGuard library
# Following library best practices: https://docs.python.org/3/howto/logging.html#configuring-logging-for-a-library
_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler()) # Add a NullHandler to prevent "No handler found" warnings

def setup_logging(level: int = logging.INFO, handler: Optional[logging.Handler] = None) -> None:
    """
    Set up logging for the QueryGuard library.

    By default, QueryGuard does not output any logs. Call this function
    in your application to enable QueryGuard's internal logging.

    Args:
        level (int): The logging level to set for QueryGuard's logger
                     (e.g., logging.DEBUG, logging.INFO, logging.WARNING).
                     Defaults to logging.INFO.
        handler (Optional[logging.Handler]): The logging handler to use.
                                             If None, a StreamHandler outputting
                                             to sys.stderr will be created.
                                             Defaults to None.
    """
    # Remove the NullHandler if it exists to avoid duplicate logs if setup_logging is called multiple times
    for h in list(_logger.handlers): # Iterate over a copy
        if isinstance(h, logging.NullHandler):
            _logger.removeHandler(h)

    if handler is None:
        # Default to a StreamHandler to stderr if no handler is provided
        handler = logging.StreamHandler()
        # You might want a default formatter as well
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

    _logger.addHandler(handler)
    _logger.setLevel(level)
    _logger.info(f"QueryGuard logging configured at level {logging.getLevelName(level)}.")

# Optional: A log message to confirm package initialization if logging is explicitly enabled by the app.
# This will only show if the application calls setup_logging().
_logger.debug(f"QueryGuard package (version {__version__}) initialized and logger ready.")
