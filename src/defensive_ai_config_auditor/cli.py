from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evaluator import evaluate, load_cases, validate_cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and evaluate the defensive configuration benchmark")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate benchmark YAML files")
    validate.add_argument("benchmark", type=Path)
    validate.add_argument("--schema", type=Path, default=Path("schemas/case.schema.json"))
    score = sub.add_parser("evaluate", help="score a predictions JSON file")
    score.add_argument("predictions", type=Path)
    score.add_argument("benchmark", type=Path)
    args = parser.parse_args()

    if args.command == "validate":
        errors = validate_cases(args.benchmark, args.schema)
        if errors:
            print("\n".join(errors))
            return 1
        print(f"Validated {len(load_cases(args.benchmark))} cases")
        return 0

    predictions = json.loads(args.predictions.read_text(encoding="utf-8"))
    print(json.dumps(evaluate(load_cases(args.benchmark), predictions), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
