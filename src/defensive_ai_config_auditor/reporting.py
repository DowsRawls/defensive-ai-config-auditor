from __future__ import annotations

from typing import Any, Iterator

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error"}


def iter_report_findings(report: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield domain, file, and finding from a single-file or directory report."""
    reports = report.get("reports")
    if isinstance(reports, list):
        for item in reports:
            if not isinstance(item, dict):
                continue
            domain = str(item.get("domain", report.get("domain", "unknown")))
            filename = str(item.get("file", "unknown"))
            for finding in item.get("findings", []):
                if isinstance(finding, dict):
                    yield domain, filename, finding
        return

    domain = str(report.get("domain", "unknown"))
    filename = str(report.get("file", "unknown"))
    for finding in report.get("findings", []):
        if isinstance(finding, dict):
            yield domain, filename, finding


def meets_failure_threshold(report: dict[str, Any], threshold: str) -> bool:
    if threshold == "none":
        return False
    minimum = SEVERITY_ORDER[threshold]
    return any(
        SEVERITY_ORDER.get(str(finding.get("severity")), 0) >= minimum
        for _, _, finding in iter_report_findings(report)
        if "suppression" not in finding
    )


def _sarif_locations(filename: str, finding: dict[str, Any]) -> list[dict[str, Any]]:
    artifact = {"uri": filename.replace("\\", "/")}
    raw_lines = finding.get("lines", [])
    lines = sorted({line for line in raw_lines if isinstance(line, int) and line > 0})
    if not lines:
        return [{"physicalLocation": {"artifactLocation": artifact}}]
    return [
        {
            "physicalLocation": {
                "artifactLocation": artifact,
                "region": {"startLine": line},
            }
        }
        for line in lines
    ]


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    findings = list(iter_report_findings(report))
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for domain, filename, finding in findings:
        rule_id = str(finding.get("id", "unknown-finding"))
        severity = str(finding.get("severity", "medium"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": rule_id.replace("-", " ")},
                "help": {"text": str(finding.get("remediation", "Human review required."))},
                "properties": {"domain": domain, "severity": severity},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(severity, "warning"),
                "message": {
                    "text": (
                        f"{finding.get('evidence', 'Configuration risk detected')} "
                        f"Remediation: {finding.get('remediation', 'Human review required.')}"
                    )
                },
                "locations": _sarif_locations(filename, finding),
                "properties": {
                    "advisory_only": True,
                    "domain": domain,
                    "severity": severity,
                    "suppressed": "suppression" in finding,
                },
            }
        )
        suppression = finding.get("suppression")
        if isinstance(suppression, dict):
            results[-1]["suppressions"] = [
                {
                    "kind": "external",
                    "justification": str(suppression.get("reason", "Reviewed exception")),
                }
            ]
            results[-1]["properties"]["suppression_expires_on"] = str(
                suppression.get("expires_on", "")
            )

    errors = report.get("errors", []) if isinstance(report.get("errors"), list) else []
    notifications = [
        {
            "descriptor": {"id": "input-analysis-error"},
            "level": "error",
            "message": {"text": str(error.get("error", "Unknown analysis error"))},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(error.get("file", "unknown")).replace("\\", "/")}
                    }
                }
            ],
        }
        for error in errors
        if isinstance(error, dict)
    ]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Defensive AI Configuration Auditor",
                "informationUri": "https://github.com/DowsRawls/defensive-ai-config-auditor",
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "properties": {"advisory_only": True},
    }
    if notifications:
        run["invocations"] = [
            {
                "executionSuccessful": False,
                "toolExecutionNotifications": notifications,
            }
        ]

    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
