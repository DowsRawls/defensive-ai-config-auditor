from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator


def load_cases(root: Path) -> list[dict[str, Any]]:
    return [yaml.safe_load(path.read_text(encoding="utf-8")) for path in sorted(root.rglob("*.yaml"))]


def validate_cases(root: Path, schema_path: Path) -> list[str]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors: list[str] = []
    seen: set[str] = set()
    for path in sorted(root.rglob("*.yaml")):
        try:
            case = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{path}: invalid YAML: {exc}")
            continue
        for error in validator.iter_errors(case):
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            errors.append(f"{path}:{location}: {error.message}")
        case_id = case.get("id") if isinstance(case, dict) else None
        if case_id in seen:
            errors.append(f"{path}: duplicate id {case_id}")
        if case_id:
            seen.add(case_id)
    if not seen:
        errors.append(f"{root}: no YAML cases found")
    return errors


def evaluate(cases: list[dict[str, Any]], predictions: list[dict[str, Any]]) -> dict[str, Any]:
    expected = {case["id"]: {item["id"] for item in case["expected_findings"]} for case in cases}
    supplied = {item["case_id"]: item for item in predictions}
    unknown = sorted(set(supplied) - set(expected))
    if unknown:
        raise ValueError(f"unknown case ids: {', '.join(unknown)}")

    tp = fp = fn = 0
    control_cases = control_false_positives = 0
    remediation_total = remediation_valid = 0
    for case_id, wanted in expected.items():
        prediction = supplied.get(case_id, {})
        found = set(prediction.get("finding_ids", []))
        tp += len(wanted & found)
        fp += len(found - wanted)
        fn += len(wanted - found)
        if not wanted:
            control_cases += 1
            control_false_positives += int(bool(found))
        status = prediction.get("remediation_valid")
        if status is not None:
            remediation_total += 1
            remediation_valid += int(status is True)

    def ratio(a: int, b: int) -> float | None:
        return round(a / b, 4) if b else None

    return {
        "cases": len(cases), "tp": tp, "fp": fp, "fn": fn,
        "control_cases": control_cases,
        "control_false_positives": control_false_positives,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(control_false_positives, control_cases),
        "remediation_validity": ratio(remediation_valid, remediation_total),
        "remediations_assessed": remediation_total,
    }
