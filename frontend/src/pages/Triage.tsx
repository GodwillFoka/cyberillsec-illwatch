// Triage (maquette v6) : alertes CVE à qualifier, triées par priorité puis ancienneté.
// À gauche la file, à droite le panneau de détail en cinq sections ; l'alerte choisie est
// dans l'adresse (?alerte=…) pour être partagée ou retrouvée après un rechargement.
import { useEffect, useState, type KeyboardEvent } from "react";

import { useAcknowledgeAlert, useOpenIncidentFromAlert } from "../api/mutations";
import { useCveDetail, useTriageAlerts } from "../api/queries";
import type { Alert, IncidentDetail } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { LevelBadge } from "../components/Badge";
import { Breakdown, formatEpss, formatScore } from "../components/CveScore";
import { QueryState } from "../components/QueryState";
import { messages } from "../i18n/common.i18n";
import { formatAge, formatAgo, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { ALERT_REASON, levelLabel, rankOf } from "../lib/levels";
import { Link, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { useFresh } from "../lib/useFresh";
import { t } from "./Triage.i18n";

type Scope = "pending" | "all";

const RESPONDER_ROLES = new Set(["ADMIN", "ANALYST"]);

function byPriorityThenAge(a: Alert, b: Alert): number {
  return rankOf(a.priority) - rankOf(b.priority) || a.created_at.localeCompare(b.created_at);
}

const score = formatScore;

// --- File des alertes -----------------------------------------------------------------------

function AlertTable({
  alerts,
  selectedId,
  onSelect,
}: {
  alerts: Alert[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const fresh = useFresh(alerts.map((a) => a.id));
  const sorted = [...alerts].sort(byPriorityThenAge);

  function onKey(event: KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(sorted[index].id);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = sorted[index + (event.key === "ArrowDown" ? 1 : -1)];
      if (next) {
        onSelect(next.id);
        document.getElementById(`alerte-${next.id}`)?.focus();
      }
    }
  }

  return (
    <table className="table selectable" aria-label={t("tableLabel")}>
      <thead>
        <tr>
          <th>{t("colPriority")}</th>
          <th>CVE</th>
          <th className="num">{t("colScore")}</th>
          <th>{t("colOrigin")}</th>
          <th>{t("colAge")}</th>
          <th>{t("colState")}</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((alert, index) => {
          const created = parseDate(alert.created_at);
          const classes = [fresh.has(alert.id) ? "fresh" : "", alert.acknowledged_at ? "done" : ""]
            .filter(Boolean)
            .join(" ");
          return (
            <tr
              key={alert.id}
              id={`alerte-${alert.id}`}
              tabIndex={0}
              aria-current={alert.id === selectedId ? "true" : undefined}
              className={classes || undefined}
              onClick={() => onSelect(alert.id)}
              onKeyDown={(event) => onKey(event, index)}
            >
              <td>
                <LevelBadge level={alert.priority} />
              </td>
              <td className="mono">{alert.cve_id}</td>
              <td className="num mono">{score(alert.score)}</td>
              <td className="muted">{ALERT_REASON[alert.reason] ?? alert.reason}</td>
              <td className="muted">{created ? formatAge(created) : "-"}</td>
              <td>
                {alert.acknowledged_at ? (
                  <span className="badge p3">{t("acknowledged")}</span>
                ) : (
                  <span className="badge new">{t("fresh")}</span>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// --- Panneau de détail ----------------------------------------------------------------------

function AlertDetail({
  alert,
  onAcknowledged,
}: {
  alert: Alert;
  /** Appelé après acquittement : la page passe à l'alerte suivante de la file. */
  onAcknowledged: (alert: Alert) => void;
}) {
  const { utc } = useTimeZone();
  const { user } = useAuth();
  const { navigate } = useLocation();
  const cve = useCveDetail(alert.cve_id);
  const ack = useAcknowledgeAlert();
  const toIncident = useOpenIncidentFromAlert();
  const [opened, setOpened] = useState<IncidentDetail | null>(null);

  // Une autre alerte est choisie : on oublie l'issue de l'action précédente.
  useEffect(() => {
    setOpened(null);
    ack.reset();
    toIncident.reset();
  }, [alert.id]);

  const canAct = user ? RESPONDER_ROLES.has(user.role) : false;
  const created = parseDate(alert.created_at);
  const delivered = parseDate(alert.delivered_at);
  const acknowledged = parseDate(alert.acknowledged_at);
  const error = ack.error ?? toIncident.error;

  return (
    <aside className="card detail" aria-label={t("detailLabel", { cve: alert.cve_id })}>
      {/* 1. Identifiant et priorité */}
      <section>
        <div className="title">
          <LevelBadge level={alert.priority} />
          <Link className="mono" to={`/cve?cve=${encodeURIComponent(alert.cve_id)}`}>
            {alert.cve_id}
          </Link>
        </div>
        <p className="muted" style={{ margin: "4px 0 0" }}>
          {t("crossed", { reason: ALERT_REASON[alert.reason] ?? alert.reason })}
        </p>
      </section>

      {/* 2. Statut et essentiel */}
      <section>
        <h3>{t("status")}</h3>
        <dl className="facts">
          <dt>{t("score")}</dt>
          <dd className="mono">
            {score(alert.score)}
            {alert.previous_score !== null ? t("before", { score: score(alert.previous_score) }) : ""}
          </dd>
          <dt>{t("raised")}</dt>
          <dd>{created ? `${formatDateTime(created, utc)} · ${formatAgo(created)}` : "-"}</dd>
          <dt>{t("acknowledgement")}</dt>
          <dd>{acknowledged ? formatDateTime(acknowledged, utc) : t("notAcknowledged")}</dd>
          <dt>{t("notification")}</dt>
          <dd>
            {delivered
              ? t("sentAt", { at: formatDateTime(delivered, utc) })
              : alert.delivery_attempts > 0
                ? t.plural("failed", alert.delivery_attempts)
                : t("notSent")}
          </dd>
        </dl>
      </section>

      {/* 3. Éléments associés : la CVE */}
      <section>
        <h3>{t("vulnerability")}</h3>
        <QueryState query={cve}>
          {(detail) => (
            <>
              <dl className="facts">
                <dt>{t("socPriority")}</dt>
                <dd>
                  {t("remediation", { priority: levelLabel(detail.priority), hours: formatNumber(detail.sla_hours) })}
                </dd>
                <dt>CVSS</dt>
                <dd className="mono">{score(detail.cvss_score)}</dd>
                <dt>EPSS</dt>
                <dd className="mono">
                  {formatEpss(detail.epss_score)}
                </dd>
                <dt>{t("kevCatalog")}</dt>
                <dd>
                  {detail.is_kev
                    ? detail.kev_due_date
                      ? t("yesDue", { date: detail.kev_due_date })
                      : t("yes")
                    : t("no")}
                </dd>
              </dl>
              <p className="description">{detail.description}</p>
              {detail.kev_required_action && (
                <p className="muted">{t("requiredAction", { action: detail.kev_required_action })}</p>
              )}
              <h3 style={{ marginTop: 16 }}>{t("breakdown")}</h3>
              <Breakdown cve={detail} />
            </>
          )}
        </QueryState>
      </section>

      {/* 4. Historique */}
      <section>
        <h3>{t("history")}</h3>
        {cve.data && cve.data.history.length > 0 ? (
          <ul className="list">
            {[...cve.data.history].reverse().slice(0, 6).map((change) => {
              const at = parseDate(change.changed_at);
              return (
                <li key={`${change.changed_at}-${change.new_priority}`}>
                  <span className="mono muted">{at ? formatDateTime(at, utc) : "-"}</span>
                  <span>
                    {change.old_priority ? levelLabel(change.old_priority) : t("newPriority")} →{" "}
                    {levelLabel(change.new_priority)} ({score(change.new_score)}, {change.reason})
                  </span>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="muted">{cve.isPending ? messages("loading") : t("noHistory")}</p>
        )}
      </section>

      {/* 5. Actions (principale à droite) */}
      <section>
        {opened && (
          <p className="notice ok" role="status">
            {t("incidentOpened")}<Link to={`/incidents/${opened.id}`}>{opened.title}</Link>
          </p>
        )}
        {error && (
          <p className="notice error" role="alert">
            {t("refused", { message: error.message })}
          </p>
        )}
        <div className="actions">
          <button
            className="btn"
            type="button"
            disabled={!canAct || Boolean(alert.acknowledged_at) || ack.isPending}
            onClick={() => ack.mutate(alert.id, { onSuccess: () => onAcknowledged(alert) })}
          >
            {ack.isPending ? t("acknowledging") : t("acknowledge")}
          </button>
          <button
            className="btn primary"
            type="button"
            disabled={!canAct || toIncident.isPending}
            onClick={() =>
              toIncident.mutate(alert.id, {
                onSuccess: (incident) => {
                  setOpened(incident);
                },
              })
            }
          >
            {toIncident.isPending ? t("opening") : t("openIncident")}
          </button>
        </div>
        {!canAct && (
          <p className="reason">{t("rolesOnly")}</p>
        )}
        {canAct && alert.acknowledged_at && !opened && (
          <p className="reason">{t("alreadyAck")}</p>
        )}
        {opened && (
          <div className="actions" style={{ marginTop: 8 }}>
            <button className="btn quiet" type="button" onClick={() => navigate(`/incidents/${opened.id}`)}>
              {t("goToIncident")}
            </button>
          </div>
        )}
      </section>
    </aside>
  );
}

// --- Page -----------------------------------------------------------------------------------

export function Triage() {
  const { search, navigate } = useLocation();
  const [scope, setScope] = useState<Scope>("pending");
  const [flash, setFlash] = useState<string | null>(null);
  const query = useTriageAlerts(scope);
  const requested = new URLSearchParams(search).get("alerte");

  const alerts = query.data?.items ?? [];
  const selected =
    alerts.find((a) => a.id === requested) ?? (requested ? undefined : [...alerts].sort(byPriorityThenAge)[0]);

  const select = (id: string) => {
    setFlash(null);
    navigate(`/triage?alerte=${encodeURIComponent(id)}`, { replace: true });
  };

  // Après acquittement, la file avance d'elle-même : l'alerte suivante est affichée.
  const onAcknowledged = (done: Alert) => {
    const ordered = [...alerts].sort(byPriorityThenAge);
    const at = ordered.findIndex((a) => a.id === done.id);
    const next = scope === "pending" ? (ordered[at + 1] ?? ordered[at - 1]) : undefined;
    if (next) select(next.id);
    else if (scope === "pending") navigate("/triage", { replace: true }); // file vidée
    setFlash(t("acknowledgedFlash", { cve: done.cve_id }));
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("title")}</h1>
          <p>{t("subtitle")}</p>
        </div>
      </div>

      <div className="split">
        <section className="card">
          <div className="toolbar">
            <span className="muted">
              {query.data
                ? `${t.plural("count", query.data.total)}${scope === "pending" ? t("pendingSuffix") : ""}${query.data.total > alerts.length ? t("shownSuffix", { shown: alerts.length }) : ""}`
                : " "}
            </span>
            <div className="seg" role="group" aria-label={t("scopeLabel")}>
              <button type="button" aria-pressed={scope === "pending"} onClick={() => setScope("pending")}>
                {t("scopePending")}
              </button>
              <button type="button" aria-pressed={scope === "all"} onClick={() => setScope("all")}>
                {t("scopeAll")}
              </button>
            </div>
          </div>
          {flash && (
            <p className="notice ok" role="status">
              {flash}
            </p>
          )}
          <QueryState query={query} empty={(page) => page.items.length === 0}>
            {() => <AlertTable alerts={alerts} selectedId={selected?.id ?? null} onSelect={select} />}
          </QueryState>
        </section>

        {selected ? (
          <AlertDetail alert={selected} onAcknowledged={onAcknowledged} />
        ) : (
          <aside className="card detail">
            <p className="empty">
              {query.isPending
                ? messages("loading")
                : requested
                  ? t("notInList")
                  : t("emptyQueue")}
            </p>
          </aside>
        )}
      </div>
    </>
  );
}
