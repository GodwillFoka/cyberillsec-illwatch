"""Génère les tableaux Grafana d'ILLWATCH (M11, ADR-026).

    python3 scripts/grafana_dashboards.py  # écrit deploy/observability/grafana/dashboards/*.json

Les tableaux sont produits par ce script (relu en revue) plutôt qu'exportés à la main depuis
Grafana : le JSON reste cohérent avec les noms de métriques de
`illwatch/modules/observability/metrics.py`, vérifiés par `tests/test_observability.py`.
"""

import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parents[1] / "deploy" / "observability" / "grafana" / "dashboards"
DS = {"type": "prometheus", "uid": "illwatch-prometheus"}


class Layout:
    def __init__(self) -> None:
        self.x = 0
        self.y = 0
        self.row_height = 0
        self.next_id = 1

    def place(self, w: int, h: int) -> dict[str, int]:
        if self.x + w > 24:
            self.x = 0
            self.y += self.row_height
            self.row_height = 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_height = max(self.row_height, h)
        return pos

    def ident(self) -> int:
        self.next_id += 1
        return self.next_id


def panel(
    layout: Layout,
    title: str,
    kind: str,
    targets: list[tuple[str, str]],
    *,
    w: int = 12,
    h: int = 8,
    unit: str | None = None,
    description: str = "",
    thresholds: list[tuple[float | None, str]] | None = None,
    instant: bool = False,
) -> dict[str, Any]:
    defaults: dict[str, Any] = {}
    if unit:
        defaults["unit"] = unit
    if thresholds:
        defaults["thresholds"] = {
            "mode": "absolute",
            "steps": [{"value": v, "color": c} for v, c in thresholds],
        }
    return {
        "id": layout.ident(),
        "type": kind,
        "title": title,
        "description": description,
        "datasource": DS,
        "gridPos": layout.place(w, h),
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}}
        if kind == "timeseries"
        else {},
        "targets": [
            {
                "datasource": DS,
                "expr": expr,
                "legendFormat": legend,
                "refId": chr(65 + i),
                **({"instant": True, "format": "table"} if instant else {}),
            }
            for i, (expr, legend) in enumerate(targets)
        ],
    }


def dashboard(uid: str, title: str, panels: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "uid": uid,
        "title": title,
        "tags": ["illwatch"],
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 1,
        "refresh": "1m",
        "time": {"from": "now-24h", "to": "now"},
        "panels": panels,
    }


def service() -> dict[str, Any]:
    lay = Layout()
    ok = [(None, "red"), (1, "green")]
    return dashboard(
        "illwatch-service",
        "ILLWATCH: Service",
        [
            panel(
                lay,
                "API joignable",
                "stat",
                [('up{job="illwatch-api"}', "")],
                w=6,
                h=4,
                thresholds=ok,
            ),
            panel(
                lay, "PostgreSQL", "stat", [("illwatch_database_up", "")], w=6, h=4, thresholds=ok
            ),
            panel(lay, "Redis", "stat", [("illwatch_redis_up", "")], w=6, h=4, thresholds=ok),
            panel(
                lay,
                "Démarrage de l'API",
                "stat",
                [("illwatch_process_start_time_seconds * 1000", "")],
                w=6,
                h=4,
                unit="dateTimeFromNow",
                thresholds=[(None, "text")],
            ),
            panel(
                lay,
                "Requêtes par seconde (statut)",
                "timeseries",
                [("sum by (status) (rate(illwatch_http_requests_total[5m]))", "{{status}}")],
                unit="reqps",
            ),
            panel(
                lay,
                "Taux de réponses 5xx",
                "timeseries",
                [
                    (
                        'sum(rate(illwatch_http_requests_total{status=~"5.."}[5m]))'
                        " / clamp_min(sum(rate(illwatch_http_requests_total[5m])), 1e-9)",
                        "5xx",
                    )
                ],
                unit="percentunit",
            ),
            panel(
                lay,
                "Latence de l'API (p50, p95, p99)",
                "timeseries",
                [
                    (
                        f"histogram_quantile({q}, sum by (le) "
                        '(rate(illwatch_http_request_duration_seconds_bucket{route=~"/api/.*"}[5m])))',
                        f"p{int(q * 100)}",
                    )
                    for q in (0.5, 0.95, 0.99)
                ],
                unit="s",
            ),
            panel(
                lay,
                "Routes les plus lentes (p95, 1 h)",
                "table",
                [
                    (
                        "topk(10, histogram_quantile(0.95, sum by (route, le) "
                        "(rate(illwatch_http_request_duration_seconds_bucket[1h]))))",
                        "{{route}}",
                    )
                ],
                unit="s",
                instant=True,
            ),
            panel(
                lay,
                "Refus d'authentification et d'autorisation (24 h)",
                "bargauge",
                [("illwatch_audit_refusals_24h", "{{action}}")],
                w=24,
                h=6,
                description="Échecs et refus consignés au journal d'audit, par action.",
            ),
        ],
    )


def cti() -> dict[str, Any]:
    lay = Layout()
    return dashboard(
        "illwatch-cti",
        "ILLWATCH : Collecte et SOC",
        [
            panel(
                lay,
                "IOC actifs",
                "stat",
                [("sum(illwatch_indicators_active)", "")],
                w=6,
                h=4,
                thresholds=[(None, "text")],
            ),
            panel(
                lay,
                "Nouveaux IOC (24 h)",
                "stat",
                [("illwatch_indicators_new_24h", "")],
                w=6,
                h=4,
                thresholds=[(None, "text")],
            ),
            panel(
                lay,
                "Collectes en échec (24 h)",
                "stat",
                [('illwatch_collection_runs_24h{result="failed"}', "")],
                w=6,
                h=4,
                thresholds=[(None, "green"), (1, "orange"), (10, "red")],
            ),
            panel(
                lay,
                "Sources en bon état",
                "stat",
                [("sum(illwatch_feed_healthy) / count(illwatch_feed_healthy)", "")],
                w=6,
                h=4,
                unit="percentunit",
                thresholds=[(None, "red"), (0.8, "orange"), (1, "green")],
            ),
            panel(
                lay,
                "IOC actifs par type",
                "timeseries",
                [("illwatch_indicators_active", "{{type}}")],
            ),
            panel(
                lay,
                "Âge de la dernière collecte réussie",
                "bargauge",
                [("time() - illwatch_feed_last_success_timestamp_seconds", "{{feed}}")],
                unit="s",
                thresholds=[(None, "green"), (7200, "orange"), (86400, "red")],
            ),
            panel(
                lay,
                "Synchronisations (NVD, KEV, EPSS…)",
                "bargauge",
                [("time() - illwatch_collector_last_success_timestamp_seconds", "{{collector}}")],
                unit="s",
                thresholds=[(None, "green"), (43200, "orange"), (86400, "red")],
            ),
            panel(
                lay,
                "Incidents ouverts (sévérité, niveau)",
                "timeseries",
                [("sum by (severity) (illwatch_incidents_open)", "{{severity}}")],
            ),
            panel(
                lay,
                "Évènements corrélés non acquittés",
                "timeseries",
                [("illwatch_correlated_events_unacknowledged", "{{priority}}")],
                w=24,
            ),
        ],
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, board in (("service", service()), ("collecte-soc", cti())):
        (OUT / f"illwatch-{name}.json").write_text(
            json.dumps(board, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"deploy/observability/grafana/dashboards/illwatch-{name}.json")


if __name__ == "__main__":
    main()
