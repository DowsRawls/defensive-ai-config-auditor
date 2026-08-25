from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import DOMAINS, AnalysisError, analyze_file
from .evaluator import evaluate, load_cases, validate_cases, validate_predictions


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze configurations and evaluate benchmark results")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="run deterministic defensive checks on a configuration")
    analyze.add_argument("config", type=Path)
    analyze.add_argument("--domain", choices=DOMAINS, required=True)
    validate = sub.add_parser("validate", help="validate benchmark YAML files")
    validate.add_argument("benchmark", type=Path)
    validate.add_argument("--schema", type=Path, default=Path("schemas/case.schema.json"))
    score = sub.add_parser("evaluate", help="score a predictions JSON file")
    score.add_argument("predictions", type=Path)
    score.add_argument("benchmark", type=Path)
    score.add_argument("--schema", type=Path, default=Path("schemas/predictions.schema.json"))
    args = parser.parse_args()

    if args.command == "analyze":
        try:
            result = analyze_file(args.config, args.domain)
        except AnalysisError as exc:
            print(f"Could not analyze configuration: {exc}")
            return 1
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "validate":
        errors = validate_cases(args.benchmark, args.schema)
        if errors:
            print("\n".join(errors))
            return 1
        print(f"Validated {len(load_cases(args.benchmark))} cases")
        return 0

    try:
        predictions = json.loads(args.predictions.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read predictions: {exc}")
        return 1
    cases = load_cases(args.benchmark)
    errors = validate_predictions(predictions, args.schema, {case["id"] for case in cases})
    if errors:
        print("\n".join(errors))
        return 1
    print(json.dumps(evaluate(cases, predictions), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
