from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import DOMAINS, AnalysisError, analyze_file, scan_directory
from .evaluator import evaluate, load_cases, validate_cases, validate_predictions
from .reporting import meets_failure_threshold, to_sarif
from .suppressions import SuppressionError, apply_suppressions, load_suppressions


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("json", "sarif"), default="json")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high"),
        default="none",
        help="return exit code 2 when a finding meets this severity threshold",
    )
    parser.add_argument(
        "--suppressions",
        type=Path,
        help="JSON file of reviewed, time-limited finding suppressions",
    )


def _apply_requested_suppressions(report: dict, path: Path | None) -> None:
    if path is not None:
        apply_suppressions(report, load_suppressions(path))


def _print_report(report: dict, output_format: str) -> None:
    output = to_sarif(report) if output_format == "sarif" else report
    print(json.dumps(output, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze configurations and evaluate benchmark results")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="run deterministic defensive checks on a configuration")
    analyze.add_argument("config", type=Path)
    analyze.add_argument("--domain", choices=DOMAINS, required=True)
    _add_output_options(analyze)
    scan = sub.add_parser("scan", help="analyze an explicitly selected set of files below a directory")
    scan.add_argument("root", type=Path)
    scan.add_argument("--domain", choices=DOMAINS, required=True)
    scan.add_argument("--pattern", required=True, help="relative glob, for example '**/compose*.yaml'")
    scan.add_argument("--max-files", type=int, default=100)
    _add_output_options(scan)
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
            _apply_requested_suppressions(result, args.suppressions)
        except (AnalysisError, SuppressionError) as exc:
            print(f"Could not analyze configuration: {exc}")
            return 1
        _print_report(result, args.format)
        return 2 if meets_failure_threshold(result, args.fail_on) else 0

    if args.command == "scan":
        try:
            result = scan_directory(args.root, args.domain, args.pattern, args.max_files)
            _apply_requested_suppressions(result, args.suppressions)
        except (AnalysisError, SuppressionError) as exc:
            print(f"Could not scan directory: {exc}")
            return 1
        _print_report(result, args.format)
        if result["failed_files"]:
            return 1
        return 2 if meets_failure_threshold(result, args.fail_on) else 0

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
