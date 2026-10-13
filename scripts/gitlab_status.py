"""État du dernier pipeline GitLab de `main`, remonté dans GitHub Actions.

Remplace la lecture directe de GitLab quand elle n'est pas possible (connecteur en erreur,
réseau filtré) : le résultat devient des annotations du check « Statut GitLab », lisibles
depuis l'onglet Checks d'un commit ou par l'API GitHub.

Variables : GITLAB_PROJECT (« groupe/projet »), GITLAB_REF (défaut main), GITLAB_TOKEN
(facultatif pour un projet public ; jeton personnel limité à `read_api`), WAIT_MINUTES
(attente d'un pipeline en cours, défaut 20). Bibliothèque standard uniquement.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API = "https://gitlab.com/api/v4"
RUNNING = {"created", "waiting_for_resource", "preparing", "pending", "running", "scheduled"}
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\r")
TRACE_LINES = 60


def _escape(text: str) -> str:
    """Encodage des commandes de workflow GitHub (multiligne permis)."""
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def annotate(level: str, title: str, message: str) -> None:
    safe_title = _escape(title).replace(",", "%2C").replace(":", "%3A")
    print(f"::{level} title={safe_title}::{_escape(message)}")


def get(path: str, token: str | None, *, raw: bool = False) -> Any:
    request = urllib.request.Request(f"{API}{path}")  # noqa: S310 (URL https fixe)
    if token:
        request.add_header("PRIVATE-TOKEN", token)
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 (URL fixe)
        body = response.read()
    return body.decode("utf-8", "replace") if raw else json.loads(body)


def latest_pipeline(project: str, ref: str, token: str | None) -> dict[str, Any] | None:
    pipelines = get(
        f"/projects/{project}/pipelines?ref={urllib.parse.quote(ref)}&per_page=1&order_by=id",
        token,
    )
    return pipelines[0] if pipelines else None


def main() -> int:
    project = urllib.parse.quote(os.environ.get("GITLAB_PROJECT", ""), safe="")
    ref = os.environ.get("GITLAB_REF", "main")
    token = os.environ.get("GITLAB_TOKEN") or None
    wait = int(os.environ.get("WAIT_MINUTES", "20"))
    if not project:
        annotate("error", "Statut GitLab", "GITLAB_PROJECT manquant.")
        return 1
    try:
        pipeline = latest_pipeline(project, ref, token)
        deadline = time.monotonic() + wait * 60
        while pipeline and pipeline["status"] in RUNNING and time.monotonic() < deadline:
            time.sleep(60)
            pipeline = get(f"/projects/{project}/pipelines/{pipeline['id']}", token)
        if pipeline is None:
            annotate("warning", "Statut GitLab", f"Aucun pipeline sur « {ref} ».")
            return 0
        jobs = get(f"/projects/{project}/pipelines/{pipeline['id']}/jobs?per_page=100", token)
    except urllib.error.HTTPError as error:
        hint = (
            " Projet privé : ajoutez le secret GITLAB_TOKEN (jeton personnel GitLab, portée "
            "read_api seule) dans GitHub → Settings → Secrets and variables → Actions."
            if error.code in (401, 403, 404)
            else ""
        )
        annotate("error", "Statut GitLab", f"API GitLab : HTTP {error.code}.{hint}")
        return 1

    lines = [
        f"Pipeline #{pipeline['id']} sur {ref} : {pipeline['status'].upper()}",
        f"Commit {pipeline['sha'][:12]} · mis à jour {pipeline.get('updated_at', '?')}",
        pipeline.get("web_url", ""),
        "",
    ]
    for job in sorted(jobs, key=lambda j: (j.get("stage", ""), j.get("name", ""))):
        duration = job.get("duration")
        took = f" ({duration:.0f} s)" if isinstance(duration, (int, float)) else ""
        flag = " (échec toléré)" if job.get("allow_failure") and job["status"] == "failed" else ""
        lines.append(f"[{job.get('stage')}] {job.get('name')} : {job['status']}{took}{flag}")
    level = "notice" if pipeline["status"] == "success" else "warning"
    annotate(level, f"GitLab {pipeline['status']}", "\n".join(lines))

    failed = [j for j in jobs if j["status"] == "failed"]
    for job in failed[:8]:
        try:
            trace = get(f"/projects/{project}/jobs/{job['id']}/trace", token, raw=True)
            trace = ANSI.sub("", trace)
            tail = "\n".join(trace.splitlines()[-TRACE_LINES:])
        except urllib.error.HTTPError as error:
            tail = f"(journal illisible : HTTP {error.code})"
        annotate("error", f"GitLab job {job.get('name')}", f"{job.get('web_url', '')}\n{tail}")
    blocking = [j for j in failed if not j.get("allow_failure")]
    return 1 if pipeline["status"] == "failed" and blocking else 0


if __name__ == "__main__":
    sys.exit(main())
