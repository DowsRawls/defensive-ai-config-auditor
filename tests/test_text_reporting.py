from defensive_ai_config_auditor.reporting import to_text


def test_text_shows_exceptions_baseline_errors_and_escapes_controls():
    report = {
        "domain": "nginx", "analyzed_files": 1, "failed_files": 1,
        "reports": [{"file": "a\n\x1b[31m.conf", "findings": [{
            "id": "test-rule", "severity": "high", "lines": [2, 5],
            "evidence": "explicit directive", "remediation": "Review it",
            "baseline_state": "unchanged",
            "suppression": {"reason": "Reviewed", "expires_on": "2099-01-01"},
        }]}],
        "baseline": {"new_findings_count": 0, "unchanged_findings_count": 1,
                     "resolved_findings_count": 1,
                     "resolved_findings": [{"file": "old.conf", "finding_id": "old-rule"}]},
        "errors": [{"file": "bad.conf", "error": "invalid encoding"}],
    }
    output = to_text(report)
    assert "Findings: 1 | Active: 0 | Suppressed: 1" in output
    assert "Policy eligible: low=0, medium=0, high=0" in output
    assert "a\\n\\x1b[31m.conf:2,5" in output
    assert "\x1b" not in output
    assert "suppressed, unchanged" in output
    assert "Exception: Reviewed (expires 2099-01-01)" in output
    assert "Resolved: old.conf [old-rule]" in output
    assert "ERROR: bad.conf: invalid encoding" in output


def test_text_empty_report_and_expired_exception():
    assert "Findings: 0" in to_text({"domain": "linux", "findings": []})
    output = to_text({"findings": [{
        "id": "test", "severity": "high",
        "expired_suppression": {"reason": "Old review", "expires_on": "2000-01-01"},
    }]})
    assert "(active)" in output
    assert "Expired exception: Old review" in output
    assert "Policy eligible: low=0, medium=0, high=1" in output
