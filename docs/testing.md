# Reproducible testing

The repository includes a containerized test environment so contributors do not need a local Python installation. Docker Compose builds from official Python images and installs the project with pinned direct test dependencies from `requirements/test-constraints.txt`.

## Supported versions

| Component | Tested version |
| --- | --- |
| Python baseline | 3.11.16 on Debian Trixie slim |
| Python compatibility | 3.12.14, 3.13.15, 3.14.7 on Debian Trixie slim |
| PyYAML | 6.0.3 |
| jsonschema | 4.26.0 |
| pytest | 8.4.2 |

The Python tags are deliberately patch-pinned. Dependency ranges in `pyproject.toml` remain the package compatibility contract; the constraints file makes only the test environment reproducible.

## Commands

Run the baseline validation, example evaluation, and tests:

```bash
docker compose run --rm --build test
```

Run the full Python compatibility matrix:

```bash
docker compose --profile matrix build
docker compose run --rm test
docker compose --profile matrix run --rm test-py312
docker compose --profile matrix run --rm test-py313
docker compose --profile matrix run --rm test-py314
```

The containers have a read-only root filesystem, temporary `/tmp` and pytest cache mounts, and `no-new-privileges`. They receive no Docker socket, host configuration, credentials, or production mounts.

When updating a version, change both `compose.yaml` and this document. Update dependency pins in `requirements/test-constraints.txt`, rebuild without cache, and run the full matrix before committing.
