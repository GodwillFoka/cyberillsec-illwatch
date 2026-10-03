# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md constraints.txt ./
COPY sentry ./sentry
# Versions figées par constraints.txt (M7) : l'image, la CI et le poste Kali installent
# exactement les mêmes dépendances.
RUN pip install --upgrade pip && pip install -c constraints.txt .

COPY alembic.ini ./
COPY alembic ./alembic

# Exécution sans privilèges — RNF-SEC
RUN useradd --create-home --uid 10001 sentry && chown -R sentry:sentry /app
USER sentry

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

# Au démarrage : migrations Alembic jusqu'à head, puis service HTTP (critère M1).
# Adapté à une instance unique ; en multi-réplicas, sortir la migration dans un job dédié.
# --proxy-headers : derrière un reverse proxy listé dans FORWARDED_ALLOW_IPS, l'adresse client
# réelle est lue dans X-Forwarded-For (limitation de débit, journal d'audit).
CMD ["sh", "-c", "sentry db upgrade && exec uvicorn sentry.app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --no-server-header"]
