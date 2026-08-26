from defensive_ai_config_auditor.reporting import meets_failure_threshold, to_sarif


def _scan_report():
    finding = {
        "id": "directory-listing-enabled",
        "severity": "medium",
        "evidence": "active directive: autoindex on;",
        "remediation": "Disable autoindex.",
    }
    return {
        "domain": "nginx",
        "reports": [
            {"file": "a/nginx.conf", "domain": "nginx", "findings": [finding]},
            {"file": "b/nginx.conf", "domain": "nginx", "findings": [finding]},
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


def test_sarif_has_deduplicated_rules_results_and_input_errors():
    sarif = to_sarif(_scan_report())
    run = sarif["runs"][0]

    assert sarif["version"] == "2.1.0"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert [result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in run["results"]] == [
        "a/nginx.conf",
        "b/nginx.conf",
    ]
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
            }
        ],
    }

    result = to_sarif(report)["runs"][0]["results"][0]
    assert result["ruleId"] == "privileged-container"
    assert result["level"] == "error"
    assert result["properties"]["advisory_only"] is True
