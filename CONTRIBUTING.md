# Contributing

Contributions should improve defensive measurement, reproducibility, or documentation.

1. Open an issue describing the case and why it is representative.
2. Use synthetic, minimized configuration with no secrets or identifying data.
3. Include rationale, a minimal remediation, a validation method, and human-review caveats.
4. Add or update tests; run `da-config-audit validate benchmark` and `pytest`.
5. Do not add exploit steps, live targets, weaponized payloads, or fabricated results.

If Python is not installed locally, run `docker compose run --rm --build test`. Before changing package compatibility or cutting a release, run the complete Python version matrix documented in [docs/testing.md](docs/testing.md).

Finding IDs should describe the condition rather than a product or model. Controls with no expected findings are welcome and important for false-positive measurement.
