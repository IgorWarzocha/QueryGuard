# QueryGuard - Project TODO List

This document outlines the planned tasks, improvements, and areas for future development for the QueryGuard library. Our goal is to move from the current functional alpha towards a more robust, feature-complete, and production-ready solution.

## Core Engine (`queryguard/core.py`)

* [ ] **Robust Dynamic Dispatch:** Refactor `_call_detection_function` to make the dynamic calling of detection functions more scalable and less reliant on long `if/elif` chains. Consider using a dispatch dictionary or `inspect.signature` for more robust parameter mapping.
* [ ] **Staged Rule Execution:** Implement logic in `evaluate_input_advanced` to allow for staged execution of rules (e.g., sorting/executing by rule priority, computational cost, or severity).
* [ ] **Advanced Risk Scoring:** Develop a more sophisticated `cumulative_risk_score` model. Explore options like weighted scores, score decay, or considering combinations of triggered rules. Define clear thresholds for actions based on scores.
* [ ] **Full `session_context` Integration:** Implement logic to fully utilize the `session_context` parameter to allow rules or their parameters to be dynamically adjusted based on user trust levels, application state, etc.
* [ ] **Error Handling for Rule Execution:** Enhance error handling within the rule execution loop to gracefully manage failures in individual detection functions without halting the entire process, perhaps by flagging the failed rule.

## Detection Capabilities (`queryguard/detection_functions.py`)

* [ ] **Advanced Homoglyph Detection (`detect_unicode_evasion`):** Move beyond pre-compiled lists in `critical_keywords_homoglyph_map`. Implement or integrate a more comprehensive character-by-character homoglyph mapping/comparison approach. This will likely require careful performance consideration.
* [ ] **Sophisticated Buried Instruction Detection (`detect_structural_manipulation`):** Research and implement more advanced techniques (beyond current simple heuristics) for identifying instructions semantically buried within larger texts.
* [ ] **Refine Policy Structure Regex (`detect_structural_manipulation`):** Further test and refine the regex patterns for detecting policy-like structures to improve accuracy and reduce false positives.
* [ ] **Threshold Tuning for Statistical Analysis (`analyze_text_statistics`):** Establish a methodology or provide guidance for empirically tuning thresholds for entropy, character ratios, etc., based on typical benign and malicious inputs.
* [ ] **Complex Repetition Pattern Detection (`analyze_text_statistics`):** Explore adding detection for more complex repetition patterns (e.g., "abcabcabc") beyond simple consecutive character repeats, potentially integrating with N-gram analysis.
* [ ] **Robust Tokenization for N-grams (`detect_suspicious_ngrams`):** Evaluate and potentially integrate a more robust and language-aware tokenizer than the current `split()` method for word N-grams.
* [ ] **Enhanced Encoding Detection (`detect_common_encodings`):**
    * Improve heuristics for payload likelihood (e.g., attempt safe, partial decodes; look for associated keywords like "run:", "decode:").
    * Improve accuracy of span detection for URL encoded segments.
    * Consider support for detecting less common or nested encodings if deemed necessary.

## Rule Management (`queryguard/rule_loader.py`)

* [ ] **Deep Rule Schema Validation:** Implement more comprehensive validation for the `parameters` field within each rule's `detection_logic`. This validation should be specific to the `check_function` being called, ensuring all required parameters are present and correctly typed. (Consider libraries like Pydantic or jsonschema for this, or more detailed custom validation logic).
* [ ] **Flexible Rule Loading Strategy:** Evaluate options for handling invalid rules within a ruleset (e.g., current strict approach vs. loading only valid rules and reporting errors for others).

## Utilities (`queryguard/utils.py`)

* [ ] **Formal Logging for Utilities:** Consider replacing `print` statements in error paths (e.g., `normalize_text`) with calls to a proper logging framework.

## Testing (`tests/` directory)

* [ ] **Comprehensive Unit Tests:** Develop unit tests for all functions in `utils.py`, `detection_functions.py`, `rule_loader.py`, and `core.py`.
* [ ] **Integration Tests:** Create a robust suite of integration tests that evaluate various inputs against `default_ruleset.yaml` and other custom test rulesets to ensure end-to-end functionality.
* [ ] **Automated `test_cases` Execution:** Develop a system to automatically parse and execute the `test_cases` (positive and negative) defined within the YAML rule files as part of the automated testing pipeline.
* [ ] **Performance Testing Infrastructure:** Set up basic performance profiling for key functions to identify and address bottlenecks.

## General Library Enhancements

* [ ] **Logging Framework Integration:** Replace all development `print` statements throughout the library with a configurable logging framework (e.g., Python's `logging` module).
* [ ] **API Finalization & Documentation (`queryguard/__init__.py`, `docs/`):**
    * Review and finalize the public API.
    * Write comprehensive user documentation (how to use QueryGuard, configure rules, best practices).
    * Generate API documentation for developers.
* [ ] **Packaging & Distribution (`setup.py` / `pyproject.toml`):**
    * Ensure `setup.py` is complete and robust for distribution.
    * Consider transitioning to `pyproject.toml` for modern Python packaging standards in a future release.
* [ ] **Security Audit:** Plan for a thorough security review of QueryGuard's own codebase, especially around input handling in detection functions and rule parsing.
* [ ] **Extensibility Hooks:** Design and implement the planned "hooks for users to add custom validation/checking functions" more formally.
* [ ] **`CONTRIBUTING.md`:** Create a `CONTRIBUTING.md` file with guidelines for developers wishing to contribute to the project.
* [ ] **Example Applications (`examples/`):** Add more diverse and practical examples of QueryGuard integration.

## Future Feature Considerations

* [ ] More advanced NLP techniques for detection (if performance allows).
* [ ] Machine learning-based anomaly detection (as a more advanced, optional component).
* [ ] Integration with threat intelligence feeds for rule updates.
