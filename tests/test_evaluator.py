from pathlib import Path

from defensive_ai_config_auditor.evaluator import evaluate, load_cases, validate_cases

ROOT = Path(__file__).parents[1]


def test_benchmark_is_valid_and_has_expected_size():
    errors = validate_cases(ROOT / "benchmark", ROOT / "schemas/case.schema.json")
    assert errors == []
    assert len(load_cases(ROOT / "benchmark")) == 12


def test_perfect_predictions_score_one():
    cases = load_cases(ROOT / "benchmark")
    predictions = [
        {"case_id": case["id"], "finding_ids": [f["id"] for f in case["expected_findings"]]}
        for case in cases
    ]
    result = evaluate(cases, predictions)
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["false_positive_rate"] == 0.0


def test_missing_predictions_count_as_false_negatives():
    result = evaluate(load_cases(ROOT / "benchmark"), [])
    assert result["tp"] == 0
    assert result["fn"] > 0
    assert result["remediation_validity"] is None
