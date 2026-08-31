from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, SequenceNode

from .rules import get_rule

MAX_CONFIG_BYTES = 1_000_000
MAX_SCAN_FILES = 1_000
DOMAINS = ("docker", "nginx", "linux")


class AnalysisError(ValueError):
    """Raised when an input cannot be safely analyzed."""


def _finding(
    finding_id: str,
    evidence: str,
    lines: list[int],
) -> dict[str, Any]:
    rule = get_rule(finding_id)
    finding: dict[str, Any] = {
        "id": finding_id,
        "severity": rule["severity"],
        "evidence": evidence,
        "remediation": rule["remediation"],
    }
    finding["lines"] = sorted(set(lines))
    return finding


def _mapping_entries(node: Node | None) -> dict[str, tuple[Node, Node]]:
    if not isinstance(node, MappingNode):
        return {}
    return {str(key.value): (key, value) for key, value in node.value}


def _docker_source_lines(text: str) -> tuple[dict[str, dict[str, int]], dict[str, list[int]]]:
    """Collect source marks without constructing unsafe YAML objects."""
    document_node = yaml.compose(text, Loader=yaml.SafeLoader)
    services_entry = _mapping_entries(document_node).get("services")
    if services_entry is None or not isinstance(services_entry[1], MappingNode):
        return {}, {}

    service_lines: dict[str, dict[str, int]] = {}
    volume_lines: dict[str, list[int]] = {}
    for service_key, service_node in services_entry[1].value:
        name = str(service_key.value)
        properties = _mapping_entries(service_node)
        service_lines[name] = {"service": service_key.start_mark.line + 1}
        for property_name in ("privileged", "user", "read_only"):
            entry = properties.get(property_name)
            if entry is not None:
                service_lines[name][property_name] = entry[0].start_mark.line + 1
        volumes_entry = properties.get("volumes")
        if volumes_entry is not None and isinstance(volumes_entry[1], SequenceNode):
            volume_lines[name] = [item.start_mark.line + 1 for item in volumes_entry[1].value]
    return service_lines, volume_lines


def _match_line(text: str, match: re.Match[str]) -> int:
    return text.count("\n", 0, match.start()) + 1


def _read_config(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise AnalysisError(f"configuration exceeds {MAX_CONFIG_BYTES} bytes")
        return path.read_text(encoding="utf-8")
    except AnalysisError:
        raise
    except (OSError, UnicodeError) as exc:
        raise AnalysisError(f"could not read configuration: {exc}") from exc


def _analyze_docker(text: str) -> list[dict[str, Any]]:
    try:
        document = yaml.safe_load(text)
        service_lines, volume_lines = _docker_source_lines(text)
    except yaml.YAMLError as exc:
        raise AnalysisError(f"invalid Docker Compose YAML: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("services"), dict):
        raise AnalysisError("Docker Compose input must contain a services mapping")

    findings: list[dict[str, Any]] = []
    privileged: list[str] = []
    privileged_lines: list[int] = []
    socket_writable: list[str] = []
    socket_lines: list[int] = []
    root_default: list[str] = []
    root_lines: list[int] = []
    writable_root: list[str] = []
    writable_root_lines: list[int] = []

    for name, service in document["services"].items():
        if not isinstance(service, dict):
            continue
        service_name = str(name)
        if service.get("privileged") is True:
            privileged.append(service_name)
            privileged_lines.append(service_lines.get(service_name, {}).get("privileged", 1))
        user = service.get("user")
        user_name = str(user).split(":", 1)[0] if user is not None else ""
        if user_name in {"", "0", "root"}:
            root_default.append(service_name)
            source = service_lines.get(service_name, {})
            root_lines.append(source.get("user", source.get("service", 1)))
        if service.get("read_only") is not True:
            writable_root.append(service_name)
            source = service_lines.get(service_name, {})
            writable_root_lines.append(source.get("read_only", source.get("service", 1)))
        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            continue
        for index, volume in enumerate(volumes):
            service_volume_lines = volume_lines.get(service_name, [])
            if index < len(service_volume_lines):
                source_line = service_volume_lines[index]
            else:
                source_line = service_lines.get(service_name, {}).get("service", 1)
            if isinstance(volume, str):
                parts = volume.split(":")
                if "/var/run/docker.sock" in parts[:2] and "ro" not in parts[2:]:
                    socket_writable.append(service_name)
                    socket_lines.append(source_line)
            elif isinstance(volume, dict):
                source = volume.get("source")
                target = volume.get("target")
                if (source == "/var/run/docker.sock" or target == "/var/run/docker.sock") and volume.get("read_only") is not True:
                    socket_writable.append(service_name)
                    socket_lines.append(source_line)

    if privileged:
        findings.append(_finding(
            "privileged-container",
            f"privileged: true in services: {', '.join(privileged)}",
            privileged_lines,
        ))
    if socket_writable:
        findings.append(_finding(
            "writable-docker-socket",
            f"writable Docker socket in services: {', '.join(sorted(set(socket_writable)))}",
            socket_lines,
        ))
    if root_default:
        findings.append(_finding(
            "root-user-default",
            f"root or no explicit user in services: {', '.join(root_default)}",
            root_lines,
        ))
    if writable_root:
        findings.append(_finding(
            "writable-root-filesystem",
            f"read_only is not true in services: {', '.join(writable_root)}",
            writable_root_lines,
        ))
    return findings


def _active_lines(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _analyze_nginx(text: str) -> list[dict[str, Any]]:
    active = _active_lines(text)
    findings: list[dict[str, Any]] = []
    protocols = list(re.finditer(r"(?im)^[ \t]*ssl_protocols[ \t]+([^;]+);", active))
    legacy = sorted({
        version
        for match in protocols
        for version in re.findall(r"TLSv1\.1\b|TLSv1(?!\.\d)", match.group(1))
    })
    legacy_lines = [
        _match_line(active, match)
        for match in protocols
        if re.search(r"TLSv1\.1\b|TLSv1(?!\.\d)", match.group(1))
    ]
    if legacy:
        findings.append(_finding(
            "legacy-tls-protocols",
            f"ssl_protocols enables: {', '.join(legacy)}",
            legacy_lines,
        ))
    autoindex = list(re.finditer(r"(?im)^[ \t]*autoindex[ \t]+on[ \t]*;", active))
    if autoindex:
        findings.append(_finding(
            "directory-listing-enabled",
            "active directive: autoindex on;",
            [_match_line(active, match) for match in autoindex],
        ))
    return findings


def _analyze_linux(text: str) -> list[dict[str, Any]]:
    active = _active_lines(text)
    findings: list[dict[str, Any]] = []
    root_login = re.search(r"(?im)^[ \t]*PermitRootLogin[ \t]+yes[ \t]*$", active)
    password_login = re.search(r"(?im)^[ \t]*PasswordAuthentication[ \t]+yes[ \t]*$", active)
    if root_login and password_login:
        findings.append(_finding(
            "root-password-ssh-login",
            "PermitRootLogin yes and PasswordAuthentication yes are both active",
            [_match_line(active, root_login), _match_line(active, password_login)],
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


def scan_directory(
    root: Path,
    domain: str,
    pattern: str,
    max_files: int = 100,
) -> dict[str, Any]:
    """Analyze a bounded, explicitly selected set of files below a directory."""
    if domain not in DOMAINS:
        raise AnalysisError(f"unsupported domain: {domain}")
    if not 1 <= max_files <= MAX_SCAN_FILES:
        raise AnalysisError(f"max_files must be between 1 and {MAX_SCAN_FILES}")
    if not pattern or Path(pattern).is_absolute() or ".." in Path(pattern).parts:
        raise AnalysisError("pattern must be a non-empty relative glob without '..'")
    try:
        if not root.is_dir():
            raise AnalysisError("scan root must be a directory")
        if root.is_symlink():
            raise AnalysisError("scan root must not be a symbolic link")
        resolved_root = root.resolve(strict=True)
        candidates = sorted(
            (path for path in root.glob(pattern) if path.is_file()),
            key=lambda path: path.as_posix(),
        )
    except AnalysisError:
        raise
    except (OSError, ValueError) as exc:
        raise AnalysisError(f"could not enumerate scan root: {exc}") from exc

    if len(candidates) > max_files:
        raise AnalysisError(
            f"pattern matched {len(candidates)} files, exceeding max_files={max_files}"
        )

    reports: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for path in candidates:
        relative = path.relative_to(root).as_posix()
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(resolved_root)
            if path.is_symlink():
                raise AnalysisError("symbolic links are not scanned")
            report = analyze_file(path, domain)
        except (AnalysisError, OSError, ValueError) as exc:
            errors.append({"file": relative, "error": str(exc)})
            continue
        report["file"] = relative
        reports.append(report)

    return {
        "root": str(root),
        "domain": domain,
        "pattern": pattern,
        "matched_files": len(candidates),
        "analyzed_files": len(reports),
        "failed_files": len(errors),
        "findings_count": sum(report["findings_count"] for report in reports),
        "reports": reports,
        "errors": errors,
        "advisory_only": True,
    }
