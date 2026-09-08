from defensive_ai_config_auditor.reporting import summarize_report


def test_summary_counts_findings_not_lines_and_applies_policy_scope():
    report = {"baseline": {}, "reports": [{"findings": [
        {"severity": "high", "lines": [1, 2], "baseline_state": "new"},
        {"severity": "high", "baseline_state": "unchanged"},
        {"severity": "medium", "suppression": {}, "baseline_state": "new"},
        {"severity": "low", "baseline_state": "new"},
    ]}]}
    assert summarize_report(report) == {
        "total": 4, "active": 3, "suppressed": 1,
        "by_severity": {"low": 1, "medium": 1, "high": 2},
        "policy_eligible_by_severity": {"low": 1, "medium": 0, "high": 1},
    }


def test_summary_empty_and_without_baseline():
    assert summarize_report({"findings": []})["total"] == 0
    report = {"findings": [{"severity": "high"}]}
    assert summarize_report(report)["policy_eligible_by_severity"]["high"] == 1
