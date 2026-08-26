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


def test_scan_cli_outputs_aggregate_json(tmp_path):
    (tmp_path / "nginx.conf").write_text("autoindex on;\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "defensive_ai_config_auditor.cli",
            "scan",
            str(tmp_path),
            "--domain",
            "nginx",
            "--pattern",
            "*.conf",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["analyzed_files"] == 1
    assert report["findings_count"] == 1
    assert report["reports"][0]["file"] == "nginx.conf"


def test_analyze_cli_emits_sarif_and_uses_distinct_policy_exit_code(tmp_path):
    config = tmp_path / "nginx.conf"
    config.write_text("autoindex on;\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "defensive_ai_config_auditor.cli",
            "analyze",
            str(config),
            "--domain",
            "nginx",
            "--format",
            "sarif",
            "--fail-on",
            "medium",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    sarif = json.loads(result.stdout)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "directory-listing-enabled"


def test_scan_cli_returns_input_error_after_printing_report(tmp_path):
    (tmp_path / "good.conf").write_text("autoindex off;\n", encoding="utf-8")
    (tmp_path / "bad.conf").write_bytes(b"\xff")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "defensive_ai_config_auditor.cli",
            "scan",
            str(tmp_path),
            "--domain",
            "nginx",
            "--pattern",
            "*.conf",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["analyzed_files"] == 1
    assert report["failed_files"] == 1
