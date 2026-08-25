ARG PYTHON_VERSION=3.11.16-slim-trixie
FROM python:${PYTHON_VERSION}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_CONSTRAINT=/app/requirements/test-constraints.txt \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

COPY requirements/test-constraints.txt requirements/test-constraints.txt
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN python -m pip install --no-cache-dir -e ".[dev]"

COPY benchmark/ benchmark/
COPY schemas/ schemas/
COPY examples/ examples/
COPY tests/ tests/

CMD ["sh", "-c", "da-config-audit validate benchmark && da-config-audit evaluate examples/predictions.json benchmark && python -m pytest"]
