import json
import subprocess
import sys
from pathlib import Path


def test_analyze_cli_outputs_json(tmp_path):
    config = tmp_path / "nginx.conf"
    config.write_text("ssl_protocols TLSv1 TLSv1.2;\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "defensive_ai_config_auditor.cli",
            "analyze",
            str(config),
            "--domain",
            "nginx",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["domain"] == "nginx"
    assert report["findings_count"] == 1
    assert report["findings"][0]["id"] == "legacy-tls-protocols"


def test_analyze_cli_rejects_missing_file(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "defensive_ai_config_auditor.cli",
            "analyze",
            str(tmp_path / "missing.conf"),
            "--domain",
            "linux",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "Could not analyze configuration" in result.stdout
