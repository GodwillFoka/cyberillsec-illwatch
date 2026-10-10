// Vue d'ensemble (maquette v6) : ce qui demande votre attention, puis la situation, puis le
// contexte. Chaque chiffre vient du serveur ; une donnée absente s'affiche « — ».
import { useState } from "react";
import { Link } from "react-router-dom";

import {
  useFeedsHealth,
  useOpenIncidents,
  usePendingAlerts,
  useRecentActivity,
  useSeries,
  useSummary,
} from "../api/queries";
import type { Activity, Alert, FeedHealth, Incident, Metric, SeriesWindow, Summary } from "../api/types";
import { LevelBadge } from "../components/Badge";
import { Kpi } from "../components/Kpi";
import { QueryState } from "../components/QueryState";
import { SeriesChart } from "../components/SeriesChart";
import { formatAge, formatDateTime, formatNumber, formatTime, parseDate } from "../lib/format";
import { ALERT_REASON, INCIDENT_STATUS, PRIORITY_ORDER, rankOf, TONE_COLORS, toneOf } from "../lib/levels";
import { useTimeZone } from "../lib/time";
import { useFresh } from "../lib/useFresh";
import { useRealtime } from "../realtime/RealtimeProvider";

const STALE_MS = 5 * 60_000;

function Freshness({ summary }: { summary: Summary | undefined }) {
  const { utc } = useTimeZone();
  const { status, paused } = useRealtime();
  const at = parseDate(summary?.generated_at);
  if (!at) return null;
  const stale = Date.now() - at.getTime() > STALE_MS;
  return (
    <span className="muted">
      Chiffres arrêtés à <span className="mono">{formatTime(at, utc, true)}</span>
      {utc ? " UTC" : ""}
      {stale && (status !== "live" || paused) ? " · données datées" : ""}
    </span>
  );
}

// --- À traiter maintenant -------------------------------------------------------------------

function byPriorityThenAge(a: Alert, b: Alert): number {
  return rankOf(a.priority) - rankOf(b.priority) || a.created_at.localeCompare(b.created_at);
}

function AlertQueue() {
  const query = usePendingAlerts();
  const fresh = useFresh(query.data?.items.map((a) => a.id));
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>File prioritaire</h2>
          <span className="muted">
            {query.data
              ? `${formatNumber(query.data.total)} alerte${query.data.total > 1 ? "s" : ""} non traitée${query.data.total > 1 ? "s" : ""} · triées par priorité puis ancienneté`
              : "Alertes CVE non acquittées"}
          </span>
        </div>
        <Link className="btn primary" to="/triage">
          Ouvrir le triage
        </Link>
      </div>
      <QueryState query={query} empty={(page) => page.items.length === 0}>
        {(page) => (
          <table className="table">
            <thead>
              <tr>
                <th>Priorité</th>
                <th>Alerte</th>
                <th>Origine</th>
                <th>Âge</th>
                <th>
                  <span className="sr-only">Action</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {[...page.items]
                .sort(byPriorityThenAge)
                .slice(0, 5)
                .map((alert) => (
                  <tr key={alert.id} className={fresh.has(alert.id) ? "fresh" : undefined}>
                    <td>
                      <LevelBadge level={alert.priority} />
                    </td>
                    <td className="ellipsis">
                      <span className="mono">{alert.cve_id}</span> · seuil de risque franchi (score{" "}
                      {alert.score.toFixed(1).replace(".", ",")})
                    </td>
                    <td className="muted">{ALERT_REASON[alert.reason] ?? alert.reason}</td>
                    <td className="muted">{formatAge(parseDate(alert.created_at) ?? new Date())}</td>
                    <td>
                      <Link to={`/triage?alerte=${alert.id}`}>Examiner</Link>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        )}
      </QueryState>
    </section>
  );
}

function TopIncident({ incident }: { incident: Incident | undefined }) {
  if (!incident) {
    return (
      <section className="card">
        <h2>Incident le plus grave</h2>
        <p className="empty">Aucun incident ouvert.</p>
      </section>
    );
  }
  const opened = parseDate(incident.created_at);
  return (
    <section className="card">
      <div className="card-head">
        <h2>Incident le plus grave</h2>
        <LevelBadge level={incident.severity} />
      </div>
      <p className="ellipsis" title={incident.title}>
        {incident.title}
      </p>
      <p className="muted">
        Phase : {INCIDENT_STATUS[incident.status] ?? incident.status}
        {opened ? ` · ouvert il y a ${formatAge(opened)}` : ""}
      </p>
      <Link to={`/incidents/${incident.id}`}>Ouvrir l'investigation →</Link>
    </section>
  );
}

function ToHandle({ summary }: { summary: Summary | undefined }) {
  const incidents = useOpenIncidents();
  const open = summary?.incidents;
  const bySeverity = open?.open_by_severity ?? {};
  const critical = (bySeverity.CRITICAL ?? 0) + (bySeverity.HIGH ?? 0);
  return (
    <div className="grid two">
      <AlertQueue />
      <div className="grid">
        <TopIncident incident={incidents.data?.items[0]} />
        <Kpi
          label="Incidents ouverts"
          value={formatNumber(open?.open)}
          context={
            open
              ? `${formatNumber(critical)} critique(s) ou élevé(s) · ${formatNumber(open.opened_24h)} ouvert(s) en 24 h`
              : undefined
          }
        />
      </div>
    </div>
  );
}

// --- Situation ------------------------------------------------------------------------------

function Situation({ summary }: { summary: Summary | undefined }) {
  const cves = summary?.cves.by_priority ?? {};
  const degraded = summary?.feeds.degraded ?? [];
  const healthy = summary?.feeds.by_status.HEALTHY;
  return (
    <div className="grid kpis">
      <Kpi
        label="IOC actifs"
        value={formatNumber(summary?.iocs.active)}
        context={
          summary
            ? `+${formatNumber(summary.iocs.new_24h)} en 24 h · ${formatNumber(summary.iocs.multi_source)} multi-sources`
            : undefined
        }
      />
      <Kpi
        label="CVE prioritaires"
        value={formatNumber(cves.P0_CRITIQUE)}
        unit="P0"
        context={
          summary
            ? `${formatNumber(cves.P1_ELEVE)} en P1 · ${formatNumber(summary.cves.kev)} au catalogue KEV`
            : undefined
        }
      />
      <Kpi
        label="Alertes CVE"
        value={formatNumber(summary?.alerts.unacknowledged)}
        unit="à traiter"
        alert={(summary?.alerts.unacknowledged ?? 0) > 0}
        context={summary ? `${formatNumber(summary.alerts.last_24h)} émise(s) en 24 h` : undefined}
      />
      <Kpi
        label="Sources CTI"
        value={formatNumber(healthy)}
        unit={summary ? `/ ${formatNumber(summary.feeds.total)} saines` : undefined}
        alert={degraded.length > 0}
        context={
          summary
            ? degraded.length > 0
              ? `Dégradée(s) : ${degraded.join(", ")}`
              : "Toutes les sources répondent"
            : undefined
        }
      />
    </div>
  );
}

// --- Évolution ------------------------------------------------------------------------------

const METRICS: [Metric, string][] = [
  ["iocs", "Nouveaux IOC"],
  ["alerts", "Alertes"],
  ["incidents", "Incidents"],
];
const WINDOWS: [SeriesWindow, string][] = [
  ["24h", "24 h"],
  ["7d", "7 j"],
  ["30d", "30 j"],
];

function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
}: {
  options: [T, string][];
  value: T;
  onChange: (value: T) => void;
  label: string;
}) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map(([key, text]) => (
        <button key={key} type="button" aria-pressed={key === value} onClick={() => onChange(key)}>
          {text}
        </button>
      ))}
    </div>
  );
}

function Evolution() {
  const [metric, setMetric] = useState<Metric>("iocs");
  const [period, setPeriod] = useState<SeriesWindow>("24h");
  const query = useSeries(metric, period);
  const { utc } = useTimeZone();
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Évolution de la menace</h2>
          <span className="muted">
            {query.data
              ? `${formatNumber(query.data.total)} sur la période · par ${query.data.bucket === "hour" ? "heure" : "jour"}, ${utc ? "UTC" : "heure locale"}`
              : " "}
          </span>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Segmented label="Mesure" options={METRICS} value={metric} onChange={setMetric} />
          <Segmented label="Période" options={WINDOWS} value={period} onChange={setPeriod} />
        </div>
      </div>
      <QueryState query={query}>{(series) => <SeriesChart series={series} utc={utc} />}</QueryState>
    </section>
  );
}

function CvePriorities({ summary }: { summary: Summary | undefined }) {
  const counts = summary?.cves.by_priority ?? {};
  // Échelle commune à P0–P2 : P3 (maintenance) écraserait les autres barres.
  const scale = Math.max(1, ...PRIORITY_ORDER.slice(0, 3).map((p) => counts[p] ?? 0));
  return (
    <section className="card">
      <h2>CVE par priorité</h2>
      {PRIORITY_ORDER.map((priority) => {
        const count = counts[priority] ?? 0;
        return (
          <div className="bar-row" key={priority}>
            <LevelBadge level={priority} />
            <div className="bar-track">
              <div
                className="bar-fill"
                style={{
                  width: `${Math.min(100, (count / scale) * 100)}%`,
                  background: TONE_COLORS[toneOf(priority)],
                }}
              />
            </div>
            <span className="num mono">{formatNumber(summary ? count : null)}</span>
          </div>
        );
      })}
      <p className="muted">Échelle commune à P0–P2 ; P3 dépasse l'échelle.</p>
    </section>
  );
}

// --- Contexte -------------------------------------------------------------------------------

const KIND_LABEL: Record<string, string> = {
  ioc: "IOC",
  cve: "CVE",
  alert: "Alerte",
  incident: "Incident",
};

function RecentActivity() {
  const query = useRecentActivity(24);
  const { utc } = useTimeZone();
  const key = (item: Activity) => `${item.kind}:${item.reference}:${item.at}`;
  const items = query.data?.slice(0, 8);
  const fresh = useFresh(items?.map(key));
  return (
    <section className="card">
      <h2>Activité récente</h2>
      <QueryState query={query} empty={(list) => list.length === 0}>
        {() => (
          <ul className="list">
            {items?.map((item) => {
              const at = parseDate(item.at);
              return (
                <li key={key(item)} className={fresh.has(key(item)) ? "fresh" : undefined}>
                  <span className="mono muted">{at ? formatTime(at, utc) : "—"}</span>
                  <span className={`badge ${toneOf(item.level)}`}>{KIND_LABEL[item.kind] ?? item.kind}</span>
                  <span className="ellipsis" title={item.label}>
                    {item.label}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </QueryState>
    </section>
  );
}

function FeedState({ feed }: { feed: FeedHealth }) {
  if (!feed.is_active) return <span className="badge p3">Suspendue</span>;
  if (feed.status === "HEALTHY") return <span className="badge ok">Saine</span>;
  if (feed.status === "DEGRADED") return <span className="badge p0">Dégradée</span>;
  return <span className="badge p3">En attente</span>;
}

function SourcesHealth() {
  const query = useFeedsHealth();
  const { utc } = useTimeZone();
  const fresh = useFresh(query.data?.map((f) => `${f.feed_id}:${f.last_attempt_at ?? ""}`));
  return (
    <section className="card">
      <div className="card-head">
        <h2>Santé des sources</h2>
        <Link to="/sources">Détail</Link>
      </div>
      <QueryState query={query} empty={(list) => list.length === 0}>
        {(feeds) => (
          <table className="table">
            <thead>
              <tr>
                <th>Source</th>
                <th>État</th>
                <th>Dernier essai</th>
                <th className="num">Échecs 7 j</th>
              </tr>
            </thead>
            <tbody>
              {feeds.map((feed) => {
                const attempt = parseDate(feed.last_attempt_at);
                const id = `${feed.feed_id}:${feed.last_attempt_at ?? ""}`;
                return (
                  <tr key={feed.feed_id} className={fresh.has(id) ? "fresh" : undefined}>
                    <td className="ellipsis" title={feed.last_error ?? feed.name}>
                      {feed.name}
                    </td>
                    <td>
                      <FeedState feed={feed} />
                    </td>
                    <td className="muted" title={attempt ? formatDateTime(attempt, utc) : undefined}>
                      {attempt ? `il y a ${formatAge(attempt)}` : "jamais"}
                    </td>
                    <td className="num">
                      {feed.errors_7d > 0 ? `${feed.errors_7d} / ${feed.runs_7d}` : "0"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </QueryState>
    </section>
  );
}

function IocTypes({ summary }: { summary: Summary | undefined }) {
  const entries = Object.entries(summary?.iocs.active_by_type ?? {}).sort((a, b) => b[1] - a[1]);
  const top = entries.slice(0, 5);
  const others = entries.slice(5).reduce((sum, [, n]) => sum + n, 0);
  const rows = others > 0 ? [...top, ["Autres", others] as [string, number]] : top;
  const max = Math.max(1, ...rows.map(([, n]) => n));
  return (
    <section className="card">
      <h2>IOC actifs par type</h2>
      {rows.length === 0 && <p className="empty">{summary ? "Aucun IOC actif." : "Chargement…"}</p>}
      {rows.map(([type, count]) => (
        <div className="bar-row" key={type}>
          <span className="mono muted">{type}</span>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: `${(count / max) * 100}%`, background: "#9D8CFF" }} />
          </div>
          <span className="num mono">{formatNumber(count)}</span>
        </div>
      ))}
    </section>
  );
}

// --- Page -----------------------------------------------------------------------------------

export function Overview() {
  const summaryQuery = useSummary();
  const summary = summaryQuery.data;
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Vue d'ensemble</h1>
          <p>Ce qui demande votre attention, puis l'état de la plateforme</p>
        </div>
        <Freshness summary={summary} />
      </div>
      {summaryQuery.isError && (
        <p className="notice error" role="alert">
          Synthèse indisponible : {summaryQuery.error.message}
        </p>
      )}

      <h2 className="section-label">À traiter maintenant</h2>
      <ToHandle summary={summary} />

      <h2 className="section-label">Situation</h2>
      <Situation summary={summary} />
      <div className="grid two" style={{ marginTop: 16 }}>
        <Evolution />
        <CvePriorities summary={summary} />
      </div>

      <h2 className="section-label">Contexte</h2>
      <div className="grid three">
        <RecentActivity />
        <SourcesHealth />
        <IocTypes summary={summary} />
      </div>
    </>
  );
}
