import json

import pytest

from defensive_ai_config_auditor.baseline import BaselineError, apply_baseline, load_baseline


def _report(filename, finding_ids):
    return {
        "domain": "nginx",
        "pattern": "*.conf",
        "reports": [{
            "file": filename,
            "domain": "nginx",
            "findings": [{"id": finding_id, "severity": "medium"} for finding_id in finding_ids],
        }],
    }


def test_baseline_marks_new_unchanged_and_resolved_findings(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(_report("nginx.conf", ["old", "resolved"])), encoding="utf-8")

    current = _report("nginx.conf", ["old", "new"])
    report = apply_baseline(current, load_baseline(path), str(path))

    assert [item["baseline_state"] for item in report["reports"][0]["findings"]] == [
        "unchanged", "new"
    ]
    assert report["baseline"]["new_findings_count"] == 1
    assert report["baseline"]["unchanged_findings_count"] == 1
    assert report["baseline"]["resolved_findings"] == [{
        "domain": "nginx", "file": "nginx.conf", "finding_id": "resolved"
    }]


@pytest.mark.parametrize("document", [{}, {"domain": "nginx"}, {"domain": 1, "findings": []}])
def test_invalid_baseline_is_rejected(tmp_path, document):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_mismatched_scan_scope_is_rejected():
    current = _report("nginx.conf", ["old"])
    baseline = _report("nginx.conf", ["old"])
    baseline["pattern"] = "**/*.conf"

    with pytest.raises(BaselineError, match="pattern"):
        apply_baseline(current, baseline, "baseline.json")
