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

### Docker

For a reproducible test run without installing Python locally:

```bash
docker compose run --rm --build test
```

The Docker setup pins a Python 3.11 baseline and provides a compatibility matrix for Python 3.12, 3.13, and 3.14. See [reproducible testing](docs/testing.md) for the exact versions and commands.

## Analyze a configuration

Run transparent, deterministic checks on a local Docker Compose, Nginx, or SSH configuration:

```bash
da-config-audit analyze compose.yaml --domain docker
da-config-audit analyze nginx.conf --domain nginx
da-config-audit analyze sshd_config --domain linux
da-config-audit scan services --domain docker --pattern "**/compose*.yaml"
da-config-audit analyze compose.yaml --domain docker --format sarif --fail-on high
da-config-audit scan nginx --domain nginx --pattern "**/*.conf" --suppressions suppressions.json
```

The analyzer emits advisory JSON or SARIF 2.1.0, never modifies the input, and does not call a model or access the network. Directory scans require an explicit domain and relative glob, are bounded, and report per-file failures without guessing file types. Findings return success by default; CI can opt into a distinct policy exit code with `--fail-on`. Reviewed exceptions can be supplied as exact, reasoned, time-limited suppressions; findings remain visible and expired exceptions do not disable policy. Its deliberately small rule set catches explicit high-confidence conditions; it is not a complete security scanner. See [analyzer documentation](docs/analyzer.md).

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
