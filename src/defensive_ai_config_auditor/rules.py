from __future__ import annotations

from typing import Any

RULESET_VERSION = 1

_RULES: tuple[dict[str, str], ...] = (
    {
        "id": "privileged-container", "domain": "docker", "severity": "high",
        "description": "A service explicitly enables privileged mode.",
        "remediation": "Remove privileged mode and grant only individually justified capabilities.",
    },
    {
        "id": "writable-docker-socket", "domain": "docker", "severity": "high",
        "description": "The Docker socket is mounted without read-only mode.",
        "remediation": "Remove the socket mount or use a narrowly scoped authenticated intermediary.",
    },
    {
        "id": "root-user-default", "domain": "docker", "severity": "medium",
        "description": "A service uses root or has no explicit user.",
        "remediation": "Set a verified non-root UID and GID compatible with required file access.",
    },
    {
        "id": "writable-root-filesystem", "domain": "docker", "severity": "medium",
        "description": "A service does not explicitly enable a read-only root filesystem.",
        "remediation": "Set read_only to true and declare only the required writable mounts.",
    },
    {
        "id": "legacy-tls-protocols", "domain": "nginx", "severity": "high",
        "description": "An active ssl_protocols directive enables TLS 1.0 or 1.1.",
        "remediation": "Permit organization-approved modern TLS versions, normally TLSv1.2 and TLSv1.3.",
    },
    {
        "id": "directory-listing-enabled", "domain": "nginx", "severity": "medium",
        "description": "An active directive enables autoindex.",
        "remediation": "Disable autoindex unless directory browsing is an explicit reviewed requirement.",
    },
    {
        "id": "root-password-ssh-login", "domain": "linux", "severity": "high",
        "description": "Direct root login and password authentication are both enabled.",
        "remediation": "Prohibit direct root login and use named accounts with audited elevation.",
    },
)

_RULES_BY_ID = {rule["id"]: rule for rule in _RULES}


def get_rule(rule_id: str) -> dict[str, str]:
    """Return immutable-by-convention metadata for a known analyzer rule."""
    return _RULES_BY_ID[rule_id]


def rules_for_domain(domain: str) -> tuple[str, ...]:
    return tuple(sorted(rule["id"] for rule in _RULES if rule["domain"] == domain))


def rules_report() -> dict[str, Any]:
    """Return a stable machine-readable catalog without exposing internal objects."""
    rules = [dict(rule) for rule in sorted(_RULES, key=lambda item: (item["domain"], item["id"]))]
    return {
        "ruleset_version": RULESET_VERSION,
        "rules_count": len(rules),
        "rules": rules,
        "advisory_only": True,
    }
