from pathlib import Path

import pytest

from defensive_ai_config_auditor.analyzer import AnalysisError, MAX_CONFIG_BYTES, analyze_file


def _analyze(tmp_path: Path, domain: str, content: str):
    config = tmp_path / "config"
    config.write_text(content, encoding="utf-8")
    return analyze_file(config, domain)


def test_docker_finds_explicit_high_and_medium_risks(tmp_path):
    result = _analyze(
        tmp_path,
        "docker",
        """
services:
  helper:
    image: example/helper:1
    privileged: true
    user: root
    read_only: false
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
""",
    )
    assert {finding["id"] for finding in result["findings"]} == {
        "privileged-container",
        "writable-docker-socket",
        "root-user-default",
        "writable-root-filesystem",
    }
    assert result["advisory_only"] is True


def test_docker_control_has_no_findings(tmp_path):
    result = _analyze(
        tmp_path,
        "docker",
        """
services:
  app:
    image: example/app:1
    user: "10001:10001"
    read_only: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
""",
    )
    assert result["findings"] == []


def test_docker_malformed_volume_mapping_does_not_crash(tmp_path):
    result = _analyze(
        tmp_path,
        "docker",
        """
services:
  app:
    user: "10001:10001"
    read_only: true
    volumes:
      - source: [invalid, list]
        target: /data
""",
    )
    assert result["findings"] == []


def test_nginx_ignores_comments_and_finds_active_directives(tmp_path):
    result = _analyze(
        tmp_path,
        "nginx",
        """
# ssl_protocols TLSv1;
ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
autoindex on;
""",
    )
    assert {finding["id"] for finding in result["findings"]} == {
        "legacy-tls-protocols",
        "directory-listing-enabled",
    }


def test_nginx_modern_tls_is_not_mistaken_for_tls_v1(tmp_path):
    result = _analyze(tmp_path, "nginx", "ssl_protocols TLSv1.2 TLSv1.3;\n")
    assert result["findings"] == []


def test_linux_requires_root_and_password_login_together(tmp_path):
    safe = _analyze(tmp_path, "linux", "PermitRootLogin no\nPasswordAuthentication yes\n")
    assert safe["findings"] == []
    unsafe = _analyze(tmp_path, "linux", "PermitRootLogin yes\nPasswordAuthentication yes\n")
    assert [finding["id"] for finding in unsafe["findings"]] == ["root-password-ssh-login"]


def test_rejects_invalid_docker_yaml(tmp_path):
    with pytest.raises(AnalysisError, match="invalid Docker Compose YAML"):
        _analyze(tmp_path, "docker", "services: [")


def test_rejects_oversized_input(tmp_path):
    config = tmp_path / "large.conf"
    config.write_bytes(b"x" * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(AnalysisError, match="exceeds"):
        analyze_file(config, "nginx")


def test_rejects_unsupported_domain(tmp_path):
    config = tmp_path / "config"
    config.write_text("test", encoding="utf-8")
    with pytest.raises(AnalysisError, match="unsupported domain"):
        analyze_file(config, "unknown")
