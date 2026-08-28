from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from .analyzer import MAX_CONFIG_BYTES
from .reporting import iter_report_findings

MAX_SUPPRESSIONS = 1_000


class SuppressionError(ValueError):
    """Raised when a suppression file is unsafe or malformed."""


def _normalized_file(value: object) -> str:
    return str(value).replace("\\", "/")


def load_suppressions(path: Path) -> list[dict[str, str]]:
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise SuppressionError(f"suppression file exceeds {MAX_CONFIG_BYTES} bytes")
        document = json.loads(path.read_text(encoding="utf-8"))
    except SuppressionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SuppressionError(f"could not read suppression file: {exc}") from exc

    if not isinstance(document, dict) or set(document) != {"version", "suppressions"}:
        raise SuppressionError("suppression file must contain only version and suppressions")
    if document["version"] != 1 or not isinstance(document["suppressions"], list):
        raise SuppressionError("suppression file version must be 1 and suppressions must be a list")
    if len(document["suppressions"]) > MAX_SUPPRESSIONS:
        raise SuppressionError(f"suppression file exceeds {MAX_SUPPRESSIONS} entries")

    required = {"finding_id", "file", "reason", "expires_on"}
    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(document["suppressions"], start=1):
        if not isinstance(raw, dict) or set(raw) != required:
            raise SuppressionError(f"suppression {index} must contain exactly {sorted(required)}")
        if not all(isinstance(raw[field], str) and raw[field].strip() for field in required):
            raise SuppressionError(f"suppression {index} fields must be non-empty strings")
        try:
            date.fromisoformat(raw["expires_on"])
        except ValueError as exc:
            raise SuppressionError(f"suppression {index} expires_on must be YYYY-MM-DD") from exc
        entry = {field: raw[field].strip() for field in required}
        entry["file"] = _normalized_file(entry["file"])
        key = (entry["file"], entry["finding_id"])
        if key in seen:
            raise SuppressionError(f"duplicate suppression for {entry['file']} and {entry['finding_id']}")
        seen.add(key)
        entries.append(entry)
    return entries


def apply_suppressions(
    report: dict[str, Any],
    entries: list[dict[str, str]],
    today: date | None = None,
) -> dict[str, Any]:
    """Annotate matching findings while retaining them in the report."""
    current_date = today or date.today()
    configured = {(entry["file"], entry["finding_id"]): entry for entry in entries}
    matched: set[tuple[str, str]] = set()
    applied = 0
    expired = 0

    for _, filename, finding in iter_report_findings(report):
        key = (_normalized_file(filename), str(finding.get("id", "")))
        entry = configured.get(key)
        if entry is None:
            continue
        matched.add(key)
        metadata = {"reason": entry["reason"], "expires_on": entry["expires_on"]}
        if date.fromisoformat(entry["expires_on"]) < current_date:
            finding["expired_suppression"] = metadata
            expired += 1
        else:
            finding["suppression"] = metadata
            applied += 1

    total = sum(1 for _ in iter_report_findings(report))
    report["active_findings_count"] = total - applied
    report["suppressed_findings_count"] = applied
    report["suppression_summary"] = {
        "configured": len(entries),
        "applied": applied,
        "expired": expired,
        "unmatched": len(configured) - len(matched),
    }
    return report
