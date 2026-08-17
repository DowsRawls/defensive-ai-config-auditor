from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evaluator import evaluate, load_cases, validate_cases, validate_predictions


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and evaluate the defensive configuration benchmark")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate benchmark YAML files")
    validate.add_argument("benchmark", type=Path)
    validate.add_argument("--schema", type=Path, default=Path("schemas/case.schema.json"))
    score = sub.add_parser("evaluate", help="score a predictions JSON file")
    score.add_argument("predictions", type=Path)
    score.add_argument("benchmark", type=Path)
    score.add_argument("--schema", type=Path, default=Path("schemas/predictions.schema.json"))
    args = parser.parse_args()

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
