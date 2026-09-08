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


def summarize_report(report: dict[str, Any]) -> dict[str, Any]:
    """Count current findings after suppressions and baseline annotation."""
    findings = [finding for _, _, finding in iter_report_findings(report)]
    active = [finding for finding in findings if "suppression" not in finding]
    eligible = [
        finding for finding in active
        if "baseline" not in report or finding.get("baseline_state") == "new"
    ]
    return {
        "total": len(findings),
        "active": len(active),
        "suppressed": len(findings) - len(active),
        "by_severity": {
            severity: sum(finding.get("severity") == severity for finding in findings)
            for severity in SEVERITY_ORDER
        },
        "policy_eligible_by_severity": {
            severity: sum(finding.get("severity") == severity for finding in eligible)
            for severity in SEVERITY_ORDER
        },
    }


def meets_failure_threshold(
    report: dict[str, Any],
    threshold: str,
    only_new: bool = False,
) -> bool:
    if threshold == "none":
        return False
    minimum = SEVERITY_ORDER[threshold]
    return any(
        SEVERITY_ORDER.get(str(finding.get("severity")), 0) >= minimum
        for _, _, finding in iter_report_findings(report)
        if "suppression" not in finding
        if not only_new or finding.get("baseline_state") == "new"
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
        baseline_state = finding.get("baseline_state")
        if baseline_state in {"new", "unchanged"}:
            results[-1]["baselineState"] = baseline_state

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


def _terminal_text(value: Any) -> str:
    """Escape control characters so input cannot inject terminal commands or lines."""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in str(value)
    )


def to_text(report: dict[str, Any]) -> str:
    summary = summarize_report(report)
    lines = [
        "Defensive AI Configuration Auditor (advisory only)",
        f"Domain: {_terminal_text(report.get('domain', 'unknown'))}",
        f"Findings: {summary['total']} | Active: {summary['active']} | Suppressed: {summary['suppressed']}",
        "Severity: " + ", ".join(f"{key}={value}" for key, value in summary["by_severity"].items()),
        "Policy eligible: " + ", ".join(
            f"{key}={value}" for key, value in summary["policy_eligible_by_severity"].items()
        ),
    ]
    if "reports" in report:
        lines.append(
            f"Files: analyzed={report.get('analyzed_files', 0)}, failed={report.get('failed_files', 0)}"
        )
    for _, filename, finding in iter_report_findings(report):
        status = "suppressed" if "suppression" in finding else "active"
        if "baseline_state" in finding:
            status += ", " + _terminal_text(finding["baseline_state"])
        locations = ",".join(str(line) for line in finding.get("lines", []))
        location = _terminal_text(filename) + (":" + _terminal_text(locations) if locations else "")
        lines.extend([
            "",
            f"[{_terminal_text(finding.get('severity', 'unknown')).upper()}] "
            f"{_terminal_text(finding.get('id', 'unknown'))} ({status})",
            f"  File: {location}",
            f"  Evidence: {_terminal_text(finding.get('evidence', ''))}",
            f"  Remediation: {_terminal_text(finding.get('remediation', 'Human review required.'))}",
        ])
        for key, label in (("suppression", "Exception"), ("expired_suppression", "Expired exception")):
            metadata = finding.get(key)
            if isinstance(metadata, dict):
                lines.append(
                    f"  {label}: {_terminal_text(metadata.get('reason', ''))} "
                    f"(expires {_terminal_text(metadata.get('expires_on', ''))})"
                )
    baseline = report.get("baseline")
    if isinstance(baseline, dict):
        lines.append(
            f"Baseline: new={baseline['new_findings_count']}, "
            f"unchanged={baseline['unchanged_findings_count']}, "
            f"resolved={baseline['resolved_findings_count']}"
        )
        for item in baseline.get("resolved_findings", []):
            lines.append(
                f"  Resolved: {_terminal_text(item['file'])} "
                f"[{_terminal_text(item['finding_id'])}]"
            )
    for error in report.get("errors", []):
        lines.append(
            f"ERROR: {_terminal_text(error.get('file', 'unknown'))}: "
            f"{_terminal_text(error.get('error', 'Unknown analysis error'))}"
        )
    return "\n".join(lines)
