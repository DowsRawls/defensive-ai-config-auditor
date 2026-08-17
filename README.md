# Defensive AI Configuration Auditor

An honest, minimal research MVP for evaluating whether an AI-assisted reviewer can identify and safely remediate security misconfigurations in Docker Compose, Nginx, and Linux service configurations.

This repository contains a small, defensive-only benchmark and a deterministic evaluator. It does **not** contain exploitation code, claim model performance, or automatically apply changes. Suggested remediations must be reviewed by a human and tested in an isolated environment.

## Research questions

- What precision, recall, and false-positive rate does a reviewer achieve?
- Are proposed remediations valid, minimal, and functionality-preserving?
- How often should a system abstain or escalate to a human?
- Are results stable across equivalent configuration formats?

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
da-config-audit validate benchmark
da-config-audit evaluate examples/predictions.json benchmark
pytest
```

The sample predictions are intentionally incomplete and exist only to demonstrate the file format. Their output is not a benchmark result.

Prediction files are validated against `schemas/predictions.schema.json` before scoring. Duplicate case IDs, unknown benchmark IDs, duplicate finding IDs, and unexpected fields are rejected so malformed experiment output cannot silently alter reported metrics.

## Benchmark layout

Each YAML case contains a configuration excerpt, expected defensive findings, acceptable remediation properties, and a human-review note. Cases with an empty `expected_findings` list are controls used to measure false positives.

The evaluator scores finding identifiers:

- **precision** = TP / (TP + FP)
- **recall** = TP / (TP + FN)
- **false-positive rate** = control cases with any predicted finding / all control cases
- **remediation validity** = valid submitted remediations / submitted remediations

Remediation validity is supplied by a human or isolated test harness in the prediction file; the evaluator never assumes prose is safe merely because a model produced it. If no remediation was assessed, the value is reported as `null`.

## Scope and limitations

This corpus is deliberately small (12 cases) and is suitable for pipeline development, not general claims. Expected findings are curated labels, not universal security truth. Context can change risk. No configuration is modified automatically. See [methodology](docs/methodology.md), [threat model](docs/threat-model.md), and [safety](docs/safety.md).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Licensed under the MIT License.
