# syntax=docker/dockerfile:1

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=2.4.1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install Poetry and only the runtime dependencies (the `dev` group is skipped).
# `poetry lock` keeps the build working even if poetry.lock is out of sync with pyproject.toml.
COPY pyproject.toml poetry.lock ./
RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}" \
    && poetry lock \
    && poetry install --no-root --only main

COPY app/ ./app/

# Run as an unprivileged user.
RUN useradd --create-home --uid 1000 astra
USER astra

ENTRYPOINT ["python", "-m", "app.cli"]
CMD ["--help"]
