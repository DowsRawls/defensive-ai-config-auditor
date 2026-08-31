from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .reporting import iter_report_findings
from .rules import rules_for_domain

MAX_BASELINE_BYTES = 10_000_000
MAX_BASELINE_FINDINGS = 10_000


class BaselineError(ValueError):
    """Raised when a baseline report is unsafe or malformed."""


def _finding_key(domain: str, filename: str, finding: dict[str, Any]) -> tuple[str, str, str]:
    return domain, filename.replace("\\", "/"), str(finding.get("id", ""))


def _validate_report(report: object) -> dict[str, Any]:
    if not isinstance(report, dict) or not isinstance(report.get("domain"), str):
        raise BaselineError("baseline must be a JSON analyzer report with a domain")
    single_findings = report.get("findings")
    nested_reports = report.get("reports")
    if not isinstance(single_findings, list) and not isinstance(nested_reports, list):
        raise BaselineError("baseline must contain findings or reports")
    if isinstance(single_findings, list):
        if not isinstance(report.get("file"), str) or not report["file"]:
            raise BaselineError("single-file baseline must have a non-empty file")
        report_items = [report]
    else:
        report_items = nested_reports
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("file"), str)
        or not item["file"]
        or not isinstance(item.get("findings"), list)
        for item in report_items
    ):
        raise BaselineError("every baseline report must have a file and findings list")
    if any(
        not isinstance(finding, dict)
        or not isinstance(finding.get("id"), str)
        or not finding["id"]
        for item in report_items
        for finding in item["findings"]
    ):
        raise BaselineError("every baseline finding must have a non-empty id")
    findings = list(iter_report_findings(report))
    if len(findings) > MAX_BASELINE_FINDINGS:
        raise BaselineError(f"baseline exceeds {MAX_BASELINE_FINDINGS} findings")
    enabled_rules = report.get("enabled_rules")
    if enabled_rules is not None and (
        not isinstance(enabled_rules, list)
        or any(not isinstance(rule_id, str) or not rule_id for rule_id in enabled_rules)
    ):
        raise BaselineError("baseline enabled_rules must be a list of non-empty strings")
    return report


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_BASELINE_BYTES:
            raise BaselineError(f"baseline exceeds {MAX_BASELINE_BYTES} bytes")
        report = json.loads(path.read_text(encoding="utf-8"))
    except BaselineError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"could not read baseline: {exc}") from exc
    return _validate_report(report)


def _rule_scope(report: dict[str, Any]) -> tuple[str, ...]:
    enabled_rules = report.get("enabled_rules")
    if enabled_rules is None:
        return rules_for_domain(str(report.get("domain", "")))
    return tuple(sorted(enabled_rules))


def apply_baseline(
    report: dict[str, Any],
    baseline: dict[str, Any],
    source: str,
) -> dict[str, Any]:
    """Mark current findings as new or unchanged and list resolved baseline keys."""
    if report.get("domain") != baseline.get("domain"):
        raise BaselineError("baseline domain does not match the current report")
    current_is_scan = isinstance(report.get("reports"), list)
    baseline_is_scan = isinstance(baseline.get("reports"), list)
    if current_is_scan != baseline_is_scan:
        raise BaselineError("baseline report type does not match the current report")
    if current_is_scan and report.get("pattern") != baseline.get("pattern"):
        raise BaselineError("baseline pattern does not match the current scan")
    if not current_is_scan and report.get("file") != baseline.get("file"):
        raise BaselineError("baseline file does not match the current analysis")
    if _rule_scope(report) != _rule_scope(baseline):
        raise BaselineError("baseline enabled rule set does not match the current report")

    baseline_keys = {
        _finding_key(domain, filename, finding)
        for domain, filename, finding in iter_report_findings(baseline)
    }
    current_keys: set[tuple[str, str, str]] = set()
    new_count = 0
    unchanged_count = 0
    for domain, filename, finding in iter_report_findings(report):
        key = _finding_key(domain, filename, finding)
        current_keys.add(key)
        if key in baseline_keys:
            finding["baseline_state"] = "unchanged"
            unchanged_count += 1
        else:
            finding["baseline_state"] = "new"
            new_count += 1

    resolved = [
        {"domain": domain, "file": filename, "finding_id": finding_id}
        for domain, filename, finding_id in sorted(baseline_keys - current_keys)
    ]
    report["baseline"] = {
        "file": source,
        "new_findings_count": new_count,
        "unchanged_findings_count": unchanged_count,
        "resolved_findings_count": len(resolved),
        "resolved_findings": resolved,
    }
    return report
