// Vue d'ensemble (maquette v6) : ce qui demande votre attention, puis la situation, puis le
// contexte. Chaque chiffre vient du serveur ; une donnée absente s'affiche « — ».
import { useState } from "react";


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
import { formatScore } from "../components/CveScore";
import { messages } from "../i18n/common.i18n";
import { formatAge, formatAgo, formatDateTime, formatNumber, formatTime, parseDate } from "../lib/format";
import { ALERT_REASON, CHART, INCIDENT_STATUS, PRIORITY_ORDER, rankOf, TONE_COLORS, toneOf } from "../lib/levels";
import { iocTypeLabel } from "../lib/iocs";
import { useTimeZone } from "../lib/time";
import { Link } from "../lib/router";
import { useFresh } from "../lib/useFresh";
import { useRealtime } from "../realtime/RealtimeProvider";
import { t } from "./Overview.i18n";

const STALE_MS = 5 * 60_000;

function Freshness({ summary }: { summary: Summary | undefined }) {
  const { utc } = useTimeZone();
  const { status, paused } = useRealtime();
  const at = parseDate(summary?.generated_at);
  if (!at) return null;
  const stale = Date.now() - at.getTime() > STALE_MS;
  return (
    <span className="muted">
      {t("frozenAt")}<span className="mono">{formatTime(at, utc, true)}</span>
      {utc ? " UTC" : ""}
      {stale && (status !== "live" || paused) ? t("stale") : ""}
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
          <h2>{t("queueTitle")}</h2>
          <span className="muted">
            {query.data
              ? t.plural("queueCount", query.data.total)
              : t("queueEmpty")}
          </span>
        </div>
        <Link className="btn primary" to="/triage">
          {t("openTriage")}
        </Link>
      </div>
      <QueryState query={query} empty={(page) => page.items.length === 0}>
        {(page) => (
          <table className="table">
            <thead>
              <tr>
                <th>{t("colPriority")}</th>
                <th>{t("colAlert")}</th>
                <th>{t("colOrigin")}</th>
                <th>{t("colAge")}</th>
                <th>
                  <span className="sr-only">{t("colAction")}</span>
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
                      <span className="mono">{alert.cve_id}</span>
                      {t("crossed", { score: formatScore(alert.score) })}
                    </td>
                    <td className="muted">{ALERT_REASON[alert.reason] ?? alert.reason}</td>
                    <td className="muted">{formatAge(parseDate(alert.created_at) ?? new Date())}</td>
                    <td>
                      <Link to={`/triage?alerte=${alert.id}`}>{t("examine")}</Link>
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
        <h2>{t("topIncident")}</h2>
        <p className="empty">{t("noIncident")}</p>
      </section>
    );
  }
  const opened = parseDate(incident.created_at);
  return (
    <section className="card">
      <div className="card-head">
        <h2>{t("topIncident")}</h2>
        <LevelBadge level={incident.severity} />
      </div>
      <p className="ellipsis" title={incident.title}>
        {incident.title}
      </p>
      <p className="muted">
        {t("phase", { phase: INCIDENT_STATUS[incident.status] ?? incident.status })}
        {opened ? t("openedAgo", { ago: formatAgo(opened) }) : ""}
      </p>
      <Link to={`/incidents/${incident.id}`}>{t("openInvestigation")}</Link>
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
          label={t("openIncidents")}
          value={formatNumber(open?.open)}
          context={
            open
              ? t("openContext", { critical, opened: open.opened_24h })
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
        label={t("activeIocs")}
        value={formatNumber(summary?.iocs.active)}
        context={
          summary
            ? t("iocContext", { new: summary.iocs.new_24h, multi: summary.iocs.multi_source })
            : undefined
        }
      />
      <Kpi
        label={t("priorityCves")}
        value={formatNumber(cves.P0_CRITIQUE)}
        unit="P0"
        context={
          summary
            ? t("cveContext", { p1: formatNumber(cves.P1_ELEVE), kev: summary.cves.kev })
            : undefined
        }
      />
      <Kpi
        label={t("cveAlerts")}
        value={formatNumber(summary?.alerts.unacknowledged)}
        unit={t("toHandle")}
        alert={(summary?.alerts.unacknowledged ?? 0) > 0}
        context={summary ? t("alertsContext", { count: summary.alerts.last_24h }) : undefined}
      />
      <Kpi
        label={t("sources")}
        value={formatNumber(healthy)}
        unit={summary ? t("healthyOf", { total: summary.feeds.total }) : undefined}
        alert={degraded.length > 0}
        context={
          summary
            ? degraded.length > 0
              ? t("degradedList", { list: degraded.join(", ") })
              : t("allHealthy")
            : undefined
        }
      />
    </div>
  );
}

// --- Évolution ------------------------------------------------------------------------------

const metrics = (): [Metric, string][] => [
  ["iocs", t("metricIocs")],
  ["alerts", t("metricAlerts")],
  ["incidents", t("metricIncidents")],
];
const windows = (): [SeriesWindow, string][] => [
  ["24h", t("window24h")],
  ["7d", t("window7d")],
  ["30d", t("window30d")],
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
          <h2>{t("evolution")}</h2>
          <span className="muted">
            {query.data
              ? t(query.data.bucket === "hour" ? "perHour" : "perDay", {
                  total: query.data.total,
                  zone: utc ? "UTC" : t("localTime"),
                })
              : " "}
          </span>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Segmented label={t("measure")} options={metrics()} value={metric} onChange={setMetric} />
          <Segmented label={t("period")} options={windows()} value={period} onChange={setPeriod} />
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
      <h2>{t("cveByPriority")}</h2>
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
      <p className="muted">{t("scaleNote")}</p>
    </section>
  );
}

// --- Contexte -------------------------------------------------------------------------------

const kindLabel = (kind: string): string =>
  ({ ioc: "IOC", cve: "CVE", alert: t("kindAlert"), incident: t("kindIncident") })[kind] ?? kind;

function RecentActivity() {
  const query = useRecentActivity(24);
  const { utc } = useTimeZone();
  const key = (item: Activity) => `${item.kind}:${item.reference}:${item.at}`;
  const items = query.data?.slice(0, 8);
  const fresh = useFresh(items?.map(key));
  return (
    <section className="card">
      <h2>{t("recent")}</h2>
      <QueryState query={query} empty={(list) => list.length === 0}>
        {() => (
          <ul className="list">
            {items?.map((item) => {
              const at = parseDate(item.at);
              return (
                <li key={key(item)} className={fresh.has(key(item)) ? "fresh" : undefined}>
                  <span className="mono muted">{at ? formatTime(at, utc) : "—"}</span>
                  <span className={`badge ${toneOf(item.level)}`}>{kindLabel(item.kind)}</span>
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
  if (!feed.is_active) return <span className="badge p3">{t("suspended")}</span>;
  if (feed.status === "HEALTHY") return <span className="badge ok">{t("healthy")}</span>;
  if (feed.status === "DEGRADED") return <span className="badge p0">{t("degraded")}</span>;
  return <span className="badge p3">{t("waiting")}</span>;
}

function SourcesHealth() {
  const query = useFeedsHealth();
  const { utc } = useTimeZone();
  const fresh = useFresh(query.data?.map((f) => `${f.feed_id}:${f.last_attempt_at ?? ""}`));
  return (
    <section className="card">
      <div className="card-head">
        <h2>{t("sourcesHealth")}</h2>
        <Link to="/sources">{t("detail")}</Link>
      </div>
      <QueryState query={query} empty={(list) => list.length === 0}>
        {(feeds) => (
          <table className="table">
            <thead>
              <tr>
                <th>{t("colSource")}</th>
                <th>{t("colState")}</th>
                <th>{t("colLastTry")}</th>
                <th className="num">{t("colFailures")}</th>
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
                      {attempt ? formatAgo(attempt) : t("never")}
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
  const OTHERS = "__autres__";
  const rows = others > 0 ? [...top, [OTHERS, others] as [string, number]] : top;
  const max = Math.max(1, ...rows.map(([, n]) => n));
  return (
    <section className="card">
      <h2>{t("iocByType")}</h2>
      {rows.length === 0 && <p className="empty">{summary ? t("noActiveIoc") : messages("loading")}</p>}
      {rows.map(([type, count]) => (
        <div className="bar-row" key={type}>
          <span className="muted ellipsis" title={type === OTHERS ? t("others") : type}>
            {type === OTHERS ? t("others") : iocTypeLabel(type)}
          </span>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: `${(count / max) * 100}%`, background: CHART.accent }} />
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
          <h1>{t("title")}</h1>
          <p>{t("subtitle")}</p>
        </div>
        <Freshness summary={summary} />
      </div>
      {summaryQuery.isError && (
        <p className="notice error" role="alert">
          {t("summaryError", { message: summaryQuery.error.message })}
        </p>
      )}

      <h2 className="section-label">{t("secNow")}</h2>
      <ToHandle summary={summary} />

      <h2 className="section-label">{t("secSituation")}</h2>
      <Situation summary={summary} />
      <div className="grid two" style={{ marginTop: 16 }}>
        <Evolution />
        <CvePriorities summary={summary} />
      </div>

      <h2 className="section-label">{t("secContext")}</h2>
      <div className="grid three">
        <RecentActivity />
        <SourcesHealth />
        <IocTypes summary={summary} />
      </div>
    </>
  );
}
