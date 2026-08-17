import subprocess
import sys
from pathlib import Path


def test_validate_cli():
    root = Path(__file__).parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "defensive_ai_config_auditor.cli", "validate", str(root / "benchmark"), "--schema", str(root / "schemas/case.schema.json")],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Validated 12 cases" in result.stdout


def test_evaluate_cli_rejects_unknown_case(tmp_path):
    root = Path(__file__).parents[1]
    predictions = tmp_path / "predictions.json"
    predictions.write_text('[{"case_id":"docker-999","finding_ids":[]}]', encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "defensive_ai_config_auditor.cli",
            "evaluate",
            str(predictions),
            str(root / "benchmark"),
            "--schema",
            str(root / "schemas/predictions.schema.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "unknown case id docker-999" in result.stdout
