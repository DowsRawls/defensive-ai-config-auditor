import json
from datetime import date

import pytest

from defensive_ai_config_auditor.reporting import meets_failure_threshold, to_sarif
from defensive_ai_config_auditor.suppressions import (
    SuppressionError,
    apply_suppressions,
    load_suppressions,
)


def _report():
    return {
        "domain": "nginx",
        "reports": [{
            "file": "nginx/public.conf",
            "domain": "nginx",
            "findings": [{
                "id": "directory-listing-enabled",
                "severity": "medium",
                "evidence": "active directive: autoindex on;",
                "remediation": "Disable autoindex.",
                "lines": [3],
            }],
        }],
    }


def _write_suppressions(path, expires_on):
    path.write_text(json.dumps({
        "version": 1,
        "suppressions": [{
            "finding_id": "directory-listing-enabled",
            "file": "nginx/public.conf",
            "reason": "Reviewed public mirror",
            "expires_on": expires_on,
        }],
    }), encoding="utf-8")


def test_active_suppression_is_visible_and_skipped_by_policy(tmp_path):
    path = tmp_path / "suppressions.json"
    _write_suppressions(path, "2026-12-31")

    report = apply_suppressions(_report(), load_suppressions(path), date(2026, 8, 28))

    finding = report["reports"][0]["findings"][0]
    assert finding["suppression"]["reason"] == "Reviewed public mirror"
    assert report["active_findings_count"] == 0
    assert report["suppressed_findings_count"] == 1
    assert meets_failure_threshold(report, "medium") is False
    result = to_sarif(report)["runs"][0]["results"][0]
    assert result["suppressions"][0]["kind"] == "external"


def test_expired_suppression_does_not_disable_policy(tmp_path):
    path = tmp_path / "suppressions.json"
    _write_suppressions(path, "2026-08-27")

    report = apply_suppressions(_report(), load_suppressions(path), date(2026, 8, 28))

    assert "suppression" not in report["reports"][0]["findings"][0]
    assert report["suppression_summary"]["expired"] == 1
    assert meets_failure_threshold(report, "medium") is True


@pytest.mark.parametrize("document", [
    {"version": 1, "suppressions": [{"finding_id": "x"}]},
    {"version": 2, "suppressions": []},
])
def test_malformed_suppression_file_is_rejected(tmp_path, document):
    path = tmp_path / "suppressions.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SuppressionError):
        load_suppressions(path)
