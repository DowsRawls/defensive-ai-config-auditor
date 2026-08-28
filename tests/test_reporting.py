from defensive_ai_config_auditor.reporting import meets_failure_threshold, to_sarif


def _scan_report():
    finding = {
        "id": "directory-listing-enabled",
        "severity": "medium",
        "evidence": "active directive: autoindex on;",
        "remediation": "Disable autoindex.",
        "lines": [7],
    }
    return {
        "domain": "nginx",
        "reports": [
            {"file": "a/nginx.conf", "domain": "nginx", "findings": [finding.copy()]},
            {"file": "b/nginx.conf", "domain": "nginx", "findings": [finding.copy()]},
        ],
        "errors": [{"file": "bad/nginx.conf", "error": "could not read configuration"}],
        "advisory_only": True,
    }


def test_failure_threshold_is_explicit_and_severity_aware():
    report = _scan_report()
    assert meets_failure_threshold(report, "none") is False
    assert meets_failure_threshold(report, "low") is True
    assert meets_failure_threshold(report, "medium") is True
    assert meets_failure_threshold(report, "high") is False


def test_failure_threshold_can_consider_only_new_unsuppressed_findings():
    report = _scan_report()
    report["reports"][0]["findings"][0]["baseline_state"] = "unchanged"
    report["reports"][1]["findings"][0]["baseline_state"] = "new"
    report["reports"][1]["findings"][0]["suppression"] = {
        "reason": "Reviewed", "expires_on": "2099-01-01"
    }

    assert meets_failure_threshold(report, "medium", only_new=True) is False
    results = to_sarif(report)["runs"][0]["results"]
    assert [result["baselineState"] for result in results] == ["unchanged", "new"]


def test_sarif_has_deduplicated_rules_results_and_input_errors():
    sarif = to_sarif(_scan_report())
    run = sarif["runs"][0]

    assert sarif["version"] == "2.1.0"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert [result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in run["results"]] == [
        "a/nginx.conf",
        "b/nginx.conf",
    ]
    assert [
        result["locations"][0]["physicalLocation"]["region"]["startLine"]
        for result in run["results"]
    ] == [7, 7]
    assert all(result["level"] == "warning" for result in run["results"])
    assert run["invocations"][0]["executionSuccessful"] is False
    notification = run["invocations"][0]["toolExecutionNotifications"][0]
    assert notification["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "bad/nginx.conf"


def test_sarif_single_file_high_severity_maps_to_error():
    report = {
        "file": "compose.yaml",
        "domain": "docker",
        "findings": [
            {
                "id": "privileged-container",
                "severity": "high",
                "evidence": "privileged: true in services: app",
                "remediation": "Remove privileged mode.",
                "lines": [8, 4],
            }
        ],
    }

    result = to_sarif(report)["runs"][0]["results"][0]
    assert result["ruleId"] == "privileged-container"
    assert result["level"] == "error"
    assert result["properties"]["advisory_only"] is True
    assert [
        location["physicalLocation"]["region"]["startLine"]
        for location in result["locations"]
    ] == [4, 8]
