FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="SENTRY" \
      org.opencontainers.image.description="Security Monitoring & Cyber Threat Intelligence Platform (CyberillSec)" \
      org.opencontainers.image.source="https://github.com/GodwillFoka/cyberillsec-sentry" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="CYBERILL"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Aucun paquet système ajouté à l'image de base : curl, installé autrefois pour le seul contrôle
# de santé, apportait 8 des 52 vulnérabilités « High » relevées par l'analyse d'image du 07/10
# (Container Scanning GitLab). Le contrôle de santé utilise Python, déjà présent.

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
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=4)"]

# Au démarrage : migrations Alembic jusqu'à head, puis service HTTP (critère M1).
# Adapté à une instance unique ; en multi-réplicas, sortir la migration dans un job dédié.
# --proxy-headers : derrière un reverse proxy listé dans FORWARDED_ALLOW_IPS, l'adresse client
# réelle est lue dans X-Forwarded-For (limitation de débit, journal d'audit).
# --no-access-log : le journal d'accès JSON de SENTRY (sentry.http) remplace celui d'uvicorn,
# qui doublait chaque ligne en texte libre.
CMD ["sh", "-c", "sentry db upgrade && exec uvicorn sentry.app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --no-server-header --no-access-log"]
