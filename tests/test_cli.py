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
