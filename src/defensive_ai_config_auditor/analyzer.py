from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

MAX_CONFIG_BYTES = 1_000_000
DOMAINS = ("docker", "nginx", "linux")


class AnalysisError(ValueError):
    """Raised when an input cannot be safely analyzed."""


def _finding(finding_id: str, severity: str, evidence: str, remediation: str) -> dict[str, str]:
    return {
        "id": finding_id,
        "severity": severity,
        "evidence": evidence,
        "remediation": remediation,
    }


def _read_config(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise AnalysisError(f"configuration exceeds {MAX_CONFIG_BYTES} bytes")
        return path.read_text(encoding="utf-8")
    except AnalysisError:
        raise
    except (OSError, UnicodeError) as exc:
        raise AnalysisError(f"could not read configuration: {exc}") from exc


def _analyze_docker(text: str) -> list[dict[str, str]]:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AnalysisError(f"invalid Docker Compose YAML: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("services"), dict):
        raise AnalysisError("Docker Compose input must contain a services mapping")

    findings: list[dict[str, str]] = []
    privileged: list[str] = []
    socket_writable: list[str] = []
    root_default: list[str] = []
    writable_root: list[str] = []

    for name, service in document["services"].items():
        if not isinstance(service, dict):
            continue
        service_name = str(name)
        if service.get("privileged") is True:
            privileged.append(service_name)
        user = service.get("user")
        user_name = str(user).split(":", 1)[0] if user is not None else ""
        if user_name in {"", "0", "root"}:
            root_default.append(service_name)
        if service.get("read_only") is not True:
            writable_root.append(service_name)
        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            continue
        for volume in volumes:
            if isinstance(volume, str):
                parts = volume.split(":")
                if "/var/run/docker.sock" in parts[:2] and "ro" not in parts[2:]:
                    socket_writable.append(service_name)
            elif isinstance(volume, dict):
                source = volume.get("source")
                target = volume.get("target")
                if (source == "/var/run/docker.sock" or target == "/var/run/docker.sock") and volume.get("read_only") is not True:
                    socket_writable.append(service_name)

    if privileged:
        findings.append(_finding(
            "privileged-container",
            "high",
            f"privileged: true in services: {', '.join(privileged)}",
            "Remove privileged mode and grant only individually justified capabilities.",
        ))
    if socket_writable:
        findings.append(_finding(
            "writable-docker-socket",
            "high",
            f"writable Docker socket in services: {', '.join(sorted(set(socket_writable)))}",
            "Remove the socket mount or use a narrowly scoped authenticated intermediary.",
        ))
    if root_default:
        findings.append(_finding(
            "root-user-default",
            "medium",
            f"root or no explicit user in services: {', '.join(root_default)}",
            "Set a verified non-root UID and GID compatible with required file access.",
        ))
    if writable_root:
        findings.append(_finding(
            "writable-root-filesystem",
            "medium",
            f"read_only is not true in services: {', '.join(writable_root)}",
            "Set read_only to true and declare only the required writable mounts.",
        ))
    return findings


def _active_lines(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _analyze_nginx(text: str) -> list[dict[str, str]]:
    active = _active_lines(text)
    findings: list[dict[str, str]] = []
    protocols = re.findall(r"(?im)^\s*ssl_protocols\s+([^;]+);", active)
    legacy = sorted({
        version
        for value in protocols
        for version in re.findall(r"TLSv1\.1\b|TLSv1(?!\.\d)", value)
    })
    if legacy:
        findings.append(_finding(
            "legacy-tls-protocols",
            "high",
            f"ssl_protocols enables: {', '.join(legacy)}",
            "Permit organization-approved modern TLS versions, normally TLSv1.2 and TLSv1.3.",
        ))
    if re.search(r"(?im)^\s*autoindex\s+on\s*;", active):
        findings.append(_finding(
            "directory-listing-enabled",
            "medium",
            "active directive: autoindex on;",
            "Disable autoindex unless directory browsing is an explicit reviewed requirement.",
        ))
    return findings


def _analyze_linux(text: str) -> list[dict[str, str]]:
    active = _active_lines(text)
    findings: list[dict[str, str]] = []
    root_login = re.search(r"(?im)^\s*PermitRootLogin\s+yes\s*$", active)
    password_login = re.search(r"(?im)^\s*PasswordAuthentication\s+yes\s*$", active)
    if root_login and password_login:
        findings.append(_finding(
            "root-password-ssh-login",
            "high",
            "PermitRootLogin yes and PasswordAuthentication yes are both active",
            "Prohibit direct root login and use named accounts with audited elevation.",
        ))
    return findings


def analyze_file(path: Path, domain: str) -> dict[str, Any]:
    if domain not in DOMAINS:
        raise AnalysisError(f"unsupported domain: {domain}")
    text = _read_config(path)
    analyzers = {
        "docker": _analyze_docker,
        "nginx": _analyze_nginx,
        "linux": _analyze_linux,
    }
    findings = analyzers[domain](text)
    return {
        "file": str(path),
        "domain": domain,
        "findings_count": len(findings),
        "findings": findings,
        "advisory_only": True,
    }
