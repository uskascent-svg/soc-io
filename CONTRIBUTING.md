# Contributing to SOC-IO

SOC-IO is an experimental security triage project. Contributions should improve transparency, testability, and safe handling of authorized lab data.

## Before opening a pull request
1. Explain the problem and intended behavior.
2. Keep changes scoped and document limitations.
3. Add regression tests for rule behavior and parser edge cases.
4. Never include real secrets, tokens, private keys, or sensitive telemetry.
5. Avoid claims of detection accuracy unless supported by a documented, reproducible evaluation.

## Local checks
```bash
python -m compileall -q src tests
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m socio.cli examples/events.jsonl
```

## Detection-rule contributions
Include positive and negative test cases, expected source schema, rule ID, severity rationale, false-positive considerations, and analyst follow-up guidance.

## Security changes
Describe trust boundaries and failure modes. Do not introduce network access, credential handling, or automatic response actions without a separate threat model and explicit review.
