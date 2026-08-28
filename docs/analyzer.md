# Deterministic configuration analyzer

The `analyze` command performs a small set of transparent defensive checks on one local configuration file. It does not call an AI service, access the network, execute the configuration, or modify the input.

## Usage

```bash
da-config-audit analyze path/to/config --domain docker
da-config-audit analyze path/to/nginx.conf --domain nginx
da-config-audit analyze path/to/sshd_config --domain linux
```

Analyze an explicitly selected, bounded set of files below a directory:

```bash
da-config-audit scan services --domain docker --pattern "**/compose*.yaml"
da-config-audit scan nginx --domain nginx --pattern "**/*.conf" --max-files 250
```

`scan` requires both a domain and a relative glob instead of guessing file types. It sorts matches for reproducible output, rejects parent traversal and symlink roots, limits a run to 100 files by default (1,000 maximum), and applies the per-file 1 MB limit. Invalid matched files are reported alongside successful results; nothing is modified.

With the Docker test environment, explicitly mount only the file being reviewed:

```bash
docker compose run --rm --build \
  --volume "./compose.yaml:/input/config.yaml:ro" \
  test da-config-audit analyze /input/config.yaml --domain docker
```

## CI and SARIF output

JSON remains the default. Both `analyze` and `scan` can emit SARIF 2.1.0 for code-scanning systems:

```bash
da-config-audit analyze compose.yaml --domain docker --format sarif
da-config-audit scan services --domain docker --pattern "**/compose*.yaml" --format sarif
```

Finding policy is opt-in, keeping interactive analysis advisory-only by default:

```bash
da-config-audit analyze compose.yaml --domain docker --fail-on high
da-config-audit scan services --domain docker --pattern "**/compose*.yaml" --fail-on medium
```

Exit codes are stable for CI:

- `0`: analysis completed and no enabled policy threshold was met;
- `1`: input, parsing, or scan error (the scan report is still printed when individual files fail);
- `2`: a finding met the explicit `--fail-on` severity threshold.

JSON findings include sorted, deduplicated one-based source line numbers. SARIF locations carry the same `startLine` values so code-scanning interfaces can navigate directly to each matched directive or service setting. SARIF output and exit policy never modify configurations or apply remediations.

## Reviewed suppressions

Both commands accept `--suppressions path/to/suppressions.json`. Each entry identifies an exact output `file` and `finding_id`, and requires a non-empty review reason plus an ISO `expires_on` date. See `examples/suppressions.json`.

Suppressed findings remain in JSON and SARIF output with their justification and expiry; they are excluded only from `--fail-on`. Expired entries remain active findings, while the report marks the expired exception. The summary also exposes configured, applied, expired, and unmatched entry counts. This keeps exceptions reviewable and prevents an old waiver from silently hiding risk.

## Initial rule set

| Domain | Finding ID | Condition |
| --- | --- | --- |
| Docker | `privileged-container` | A service explicitly enables privileged mode |
| Docker | `writable-docker-socket` | The Docker socket is mounted without read-only mode |
| Docker | `root-user-default` | A service uses root or has no explicit user |
| Docker | `writable-root-filesystem` | A service does not explicitly enable a read-only root filesystem |
| Nginx | `legacy-tls-protocols` | An active `ssl_protocols` directive enables TLS 1.0 or 1.1 |
| Nginx | `directory-listing-enabled` | An active directive enables `autoindex` |
| Linux | `root-password-ssh-login` | Direct root login and password authentication are both enabled |

Comments are excluded from Nginx and SSH matching. Docker Compose input is parsed with PyYAML safe loading, and source positions come from safe YAML node marks. Output evidence is limited to service names, matched directive names, and line numbers; the analyzer does not echo the full configuration.

## Limitations

The rules inspect only the supplied file. They do not resolve Nginx includes, Docker image metadata, Compose overrides, systemd defaults, or SSH configuration precedence. Missing context can change risk, and every finding requires human review. The remediation text is advisory and is never applied automatically.
