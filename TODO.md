# QueryGuard - Project TODO List

This document outlines the planned tasks, improvements, and areas for future development for the QueryGuard library. Our goal is to move from the current functional alpha towards a more robust, feature-complete, and production-ready solution.

## Core Engine (`queryguard/core.py`)

- [ ] **IMPROVE-02: Robust Dynamic Dispatch:** Refactor `_call_detection_function` to make the dynamic calling of detection functions more scalable and less reliant on long `if/elif` chains.
    - [ ] Consider using a dispatch dictionary or `inspect.signature` for more robust parameter mapping.
    - [ ] Ensure the refactored function can gracefully handle diverse return types from detection functions (e.g., booleans, lists, dictionaries with detailed findings including likelihood scores).
- [ ] **Staged Rule Execution:** Implement logic in `evaluate_input_advanced` to allow for staged execution of rules (e.g., sorting/executing by rule priority, computational cost, or severity).
- [ ] **Advanced Risk Scoring:** Develop a more sophisticated `cumulative_risk_score` model.
    - [ ] Explore options like weighted scores, score decay, or considering combinations of triggered rules.
    - [ ] Integrate detection-level likelihood/confidence scores (from detection functions) into the risk calculation.
    - [ ] Define clear thresholds for actions based on scores if desired.
- [ ] **Full `session_context` Integration:** Implement logic to fully utilize the `session_context` parameter.
    - [ ] Allow rules or their parameters to be dynamically adjusted based on user trust levels, application state, etc.
    - [ ] Enable context-aware filtering based on information passed by the host application (e.g., tags from relevant Knowledge Base documents).
- [ ] **Error Handling for Rule Execution:** Enhance error handling within the rule execution loop to gracefully manage failures in individual detection functions without halting the entire process, perhaps by flagging the failed rule.
- [ ] **Structured Findings in Evaluation Results:**
    - [ ] Enhance `triggered_rules_details` in the output of `evaluate_input_advanced` to include more granular and structured findings from detection functions (e.g., specific matched text, category of finding, count, position, likelihood).
    - [ ] Refine the top-level `message` field in the final result to clearly convey these details when appropriate, especially for blocking actions.
- [ ] **Expand `message_template` Placeholders in Rules:**
    - [ ] Allow `message_template` in rules to utilize new placeholders for granular findings (e.g., `{{matched_text}}`, `{{finding_category}}`, `{{likelihood_score}}`, `{{finding_count}}`).

## Detection Capabilities (`queryguard/detection_functions.py`)

### New Framework: User-Defined Sensitive Data Detection
- [ ] **Goal:** Allow users to define custom categories and terms/patterns of sensitive data relevant to their specific domain or project.
- [ ] **Tasks:**
    - [ ] Design a schema and loading mechanism for a user-provided configuration file (e.g., JSON or YAML) where they can list categories and associated sensitive strings or regex patterns.
    - [ ] Develop a new detection function (e.g., `detect_custom_definitions`) that:
        - [ ] Accepts a path to this user-defined configuration file as a parameter in the rule.
        - [ ] Loads and parses these definitions.
        - [ ] Scans the input text for any of the defined sensitive items.
        - [ ] Returns structured findings (e.g., matched item, category it belongs to, position).
    - [ ] Ensure this new function is integrated into the `_call_detection_function` mechanism and rule validation.

### Expanded and Enhanced Sensitive Data Detection
- [ ] **Develop/Enhance PII Detection:** Create or enhance detection functions for a broader range of Personally Identifiable Information (PII) categories (e.g., `detect_pii` covering emails, diverse phone number formats, common address patterns, etc.).
- [ ] **Develop other Generic Sensitive Data Detectors:**
    - [ ] `detect_financial_info` (e.g., common credit card patterns, bank account number hints - design for high precision).
    - [ ] `detect_credentials_patterns` (e.g., patterns for API keys, private keys, connection strings - design for high precision).
- [ ] **Introduce Likelihood/Confidence in Detection Function Results:**
    - [ ] Modify detection functions (new and existing where applicable) to return a "likelihood" or "confidence" score (e.g., a float 0.0-1.0, or categorical like LOW/MEDIUM/HIGH) for each specific finding they report. This score should reflect the function's confidence that the detected item is a true positive.

### Existing Detection Function Improvements
- [ ] **IMPROVE-03: Advanced Homoglyph Detection (`detect_unicode_evasion`):** Move beyond pre-compiled lists in `critical_keywords_homoglyph_map`. Implement or integrate a more comprehensive character-by-character homoglyph mapping/comparison approach. This will likely require careful performance consideration.
- [ ] **Sophisticated Buried Instruction Detection (`detect_structural_manipulation`):** Research and implement more advanced techniques (beyond current simple heuristics) for identifying instructions semantically buried within larger texts.
- [ ] **Refine Policy Structure Regex (`detect_structural_manipulation`):** Further test and refine the regex patterns for detecting policy-like structures to improve accuracy and reduce false positives.
- [ ] **Threshold Tuning for Statistical Analysis (`analyze_text_statistics`):** Establish a methodology or provide guidance for empirically tuning thresholds for entropy, character ratios, etc., based on typical benign and malicious inputs.
- [ ] **Complex Repetition Pattern Detection (`analyze_text_statistics`):** Explore adding detection for more complex repetition patterns (e.g., "abcabcabc") beyond simple consecutive character repeats, potentially integrating with N-gram analysis.
- [ ] **Robust Tokenization for N-grams (`detect_suspicious_ngrams`):** Evaluate and potentially integrate a more robust and language-aware tokenizer than the current `split()` method for word N-grams.
- [ ] **Enhanced Encoding Detection (`detect_common_encodings`):**
    - [ ] Improve heuristics for payload likelihood (e.g., attempt safe, partial decodes; look for associated keywords like "run:", "decode:").
    - [ ] Improve accuracy of span detection for URL encoded segments.
    - [ ] Consider support for detecting less common or nested encodings if deemed necessary.

## Rule Management (`queryguard/rule_loader.py`)

- [ ] **IMPROVE-06: Deep Rule Schema Validation:** Implement more comprehensive validation for the `parameters` field within each rule's `detection_logic`. This validation should be specific to the `check_function` being called, ensuring all required parameters are present and correctly typed. (Consider libraries like Pydantic or jsonschema for this, or more detailed custom validation logic).
    - [ ] Include validation for parameters of new detection functions (e.g., `definitions_filepath` for `detect_custom_definitions`).
- [ ] **Flexible Rule Loading Strategy:** Evaluate options for handling invalid rules within a ruleset (e.g., current strict approach vs. loading only valid rules and reporting errors for others).

## Utilities (`queryguard/utils.py`)

- [ ] **Formal Logging for Utilities:** Consider replacing `print` statements in error paths (e.g., `normalize_text`) with calls to a proper logging framework (seems `_logger` is already used, ensure consistency).

## Testing (`tests/` directory)

- [ ] **Comprehensive Unit Tests:** Develop unit tests for all functions in `utils.py`, `detection_functions.py` (including all new ones), `rule_loader.py`, and `core.py`.
- [ ] **Robust Integration Tests:** Create a robust suite of integration tests that evaluate various inputs against `default_ruleset.yaml` and other custom test rulesets to ensure end-to-end functionality.
- [ ] **Automated `test_cases` Execution:** Develop a system to automatically parse and execute the `test_cases` (positive and negative) defined within the YAML rule files as part of the automated testing pipeline.
- [ ] **Develop Diverse Test Datasets:** Create and curate datasets for testing, including examples of PII, custom user-defined sensitive terms, various injection syntaxes, and evasion techniques.
- [ ] **Performance Testing Infrastructure:** Set up basic performance profiling for key functions to identify and address bottlenecks.

## General Library Enhancements

- [ ] **Logging Framework Integration (IMPROVE-01 Finalization):** Replace all remaining development `print` statements throughout the library with a configurable logging framework (e.g., Python's `logging` module). Ensure consistency and appropriate log levels.
- [ ] **API Finalization & Documentation (`queryguard/__init__.py`, `docs/`):**
    - [ ] Review and finalize the public API.
    - [ ] Write comprehensive user documentation (how to use QueryGuard, configure rules, best practices for new features like custom data definitions and context-aware filtering using `session_context`).
    - [ ] Generate API documentation for developers.
    - [ ] Update `README.md` and `DEVELOPERS.MD` to reflect new features, advanced capabilities, and usage guidelines.
- [ ] **Packaging & Distribution (`setup.py` / `pyproject.toml`):**
    - [ ] Ensure `setup.py` is complete and robust for distribution.
    - [ ] Consider transitioning to `pyproject.toml` for modern Python packaging standards in a future release.
- [ ] **Security Audit:** Plan for a thorough security review of QueryGuard's own codebase, especially around input handling in detection functions and parsing of rule files and custom definition files.
- [ ] **Extensibility Hooks:** Design and implement the planned "hooks for users to add custom validation/checking functions" more formally. The User-Defined Sensitive Data framework is a step in this direction.
- [ ] **`CONTRIBUTING.md`:** Create a `CONTRIBUTING.md` file with guidelines for developers wishing to contribute to the project.
- [ ] **Example Applications (`examples/`):** Add more diverse and practical examples of QueryGuard integration, including showcasing new features.

## Future Feature Considerations

- [ ] More advanced NLP techniques for detection (if performance allows).
- [ ] Machine learning-based anomaly detection (as a more advanced, optional component).
- [ ] Integration with threat intelligence feeds for rule updates.
