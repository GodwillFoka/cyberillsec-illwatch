// Pilotage SOC (M9, ADR-022) : délais de prise en charge (MTTA) et de résolution (MTTR),
// respect des délais cibles par sévérité, incidents en dépassement, niveaux L1/L2/L3,
// escalades, charge par analyste et activité jour par jour, sur 7 ou 30 jours.
// Qualité des alertes (ADR-029) : issue des signaux par règle et par source, sur la même période.
import { useAlertQuality, useSocMetrics } from "../api/queries";
import type { AlertQuality, QualityRow, SocMetrics } from "../api/types";
import { LevelBadge } from "../components/Badge";
import { Kpi } from "../components/Kpi";
import { QueryState } from "../components/QueryState";
import { formatDay, formatHours, formatNumber, formatShare, parseDate } from "../lib/format";
import { CHART, TIER_LABEL, TONE_COLORS, levelLabel } from "../lib/levels";
import { Link, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { t } from "./Pilotage.i18n";

type Period = 7 | 30;

/** Nature d'un dépassement, renvoyée en français par l'API. */
const kindLabel = (kind: string) =>
  kind === "prise en charge" ? t("kindAck") : kind === "résolution" ? t("kindResolve") : kind;

function Severities({ metrics }: { metrics: SocMetrics }) {
  return (
    <section className="card">
      <h2>{t("sla")}</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        {t("slaNote")}
      </p>
      <table className="table sla-table" aria-label={t("slaTable")}>
        <thead>
          <tr>
            <th>{t("colSeverity")}</th>
            <th className="num">{t("colOpened")}</th>
            <th className="num">MTTA</th>
            <th className="num">{t("colTarget")}</th>
            <th className="num">{t("colWithin")}</th>
            <th className="num">{t("colClosed")}</th>
            <th className="num">MTTR</th>
            <th className="num">{t("colTarget")}</th>
            <th className="num">{t("colWithin")}</th>
          </tr>
        </thead>
        <tbody>
          {metrics.by_severity.map((row) => (
            <tr key={row.severity}>
              <td>
                <LevelBadge level={row.severity} />
              </td>
              <td className="num mono">{formatNumber(row.opened)}</td>
              <td className="num mono">{formatHours(row.mtta_minutes === null ? null : row.mtta_minutes / 60)}</td>
              <td className="num mono muted">{formatHours(row.ack_sla_hours)}</td>
              <td className={`num mono${row.ack_within_sla === null ? "" : row.ack_within_sla >= 0.9 ? " ok" : " late"}`}>
                {formatShare(row.ack_within_sla)}
              </td>
              <td className="num mono">{formatNumber(row.closed)}</td>
              <td className="num mono">{formatHours(row.mttr_hours)}</td>
              <td className="num mono muted">{formatHours(row.resolution_sla_hours)}</td>
              <td
                className={`num mono${row.resolved_within_sla === null ? "" : row.resolved_within_sla >= 0.9 ? " ok" : " late"}`}
              >
                {formatShare(row.resolved_within_sla)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Breaches({ metrics }: { metrics: SocMetrics }) {
  return (
    <section className="card">
      <h2>{t("breaches", { count: metrics.breaches.length })}</h2>
      {metrics.breaches.length === 0 ? (
        <p className="empty">{t("noBreach")}</p>
      ) : (
        <ul className="list">
          {metrics.breaches.map((b) => (
            <li key={b.incident_id}>
              <LevelBadge level={b.severity} />
              <span className="badge tier">{b.tier}</span>
              <span className="grow">
                <Link to={`/incidents/${b.incident_id}`}>{b.title}</Link>
                <span className="cell-sub">
                  {t("breachLine", {
                    kind: kindLabel(b.kind),
                    age: formatHours(b.age_hours),
                    target: formatHours(b.target_hours),
                  })}
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Tiers({ metrics }: { metrics: SocMetrics }) {
  const max = Math.max(1, ...Object.values(metrics.open_by_tier));
  const steps = Object.entries(metrics.escalations);
  return (
    <section className="card">
      <h2>{t("tiers")}</h2>
      {Object.entries(metrics.open_by_tier).map(([tier, count]) => (
        <div className="bar-row" key={tier}>
          <span className="muted ellipsis" title={TIER_LABEL[tier]}>
            {tier}
          </span>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: `${(count / max) * 100}%`, background: CHART.accent }} />
          </div>
          <span className="num mono">{formatNumber(count)}</span>
        </div>
      ))}
      <p className="muted small">
        {t("tiersNote", {
          list: steps.length ? steps.map(([step, n]) => `${step} × ${n}`).join(" · ") : t("noneF"),
        })}
      </p>
    </section>
  );
}

function Workload({ metrics }: { metrics: SocMetrics }) {
  return (
    <section className="card">
      <h2>{t("workload")}</h2>
      {metrics.workload.length === 0 ? (
        <p className="empty">{t("noIncident")}</p>
      ) : (
        <table className="table" aria-label={t("workload")}>
          <thead>
            <tr>
              <th>{t("colAnalyst")}</th>
              <th className="num">{t("colInProgress")}</th>
              <th className="num">{t("colClosedWindow")}</th>
            </tr>
          </thead>
          <tbody>
            {metrics.workload.map((w) => (
              <tr key={w.label}>
                <td className="cell-title">{w.label}</td>
                <td className="num mono">{formatNumber(w.open_assigned)}</td>
                <td className="num mono">{formatNumber(w.closed_in_window)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Daily({ metrics }: { metrics: SocMetrics }) {
  const { utc } = useTimeZone();
  const max = Math.max(1, ...metrics.daily.map((d) => Math.max(d.opened, d.closed)));
  return (
    <section className="card">
      <h2>{t("daily")}</h2>
      {metrics.daily.map((d) => {
        const day = parseDate(`${d.day}T12:00:00Z`);
        return (
          <div className="bar-row" key={d.day}>
            <span className="muted mono">{day ? formatDay(day, utc) : d.day}</span>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `${(d.opened / max) * 100}%`, background: TONE_COLORS.p1 }} />
            </div>
            <span className="num mono" title={t("openedClosed")}>
              {d.opened} / {d.closed}
            </span>
          </div>
        );
      })}
    </section>
  );
}

const FAMILY_LABEL: Record<QualityRow["family"], () => string> = {
  cve_alert: () => t("familyCve"),
  correlation: () => t("familyCorrelation"),
  hunt: () => t("familyHunt"),
  total: () => "",
};

/** Précision : vert dès 80 %, rouge sous 50 %, neutre sans signal qualifié. */
const precisionClass = (value: number | null) =>
  value === null ? "" : value >= 0.8 ? " ok" : value < 0.5 ? " late" : "";

function Quality({ quality }: { quality: AlertQuality }) {
  const total = quality.total;
  return (
    <section className="card">
      <h2>{t("quality")}</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        {t("qualityNote")}
      </p>
      <p>
        <strong>{t("qualityKpi")}</strong>{" "}
        <span className={`mono${precisionClass(total.precision)}`}>{formatShare(total.precision)}</span>
        <span className="muted">
          {" · "}
          {t("qualityKpiContext", { signals: formatNumber(total.signals), noise: formatShare(total.noise) })}
          {" · "}
          {t("colHandling")} {formatHours(total.handling_hours_median)}
        </span>
      </p>
      {quality.rules.length === 0 ? (
        <p className="empty">{t("noSignal")}</p>
      ) : (
        <table className="table quality-table" aria-label={t("qualityTable")}>
          <thead>
            <tr>
              <th>{t("colRule")}</th>
              <th className="num">{t("colSignals")}</th>
              <th className="num">{t("colConfirmed")}</th>
              <th className="num">{t("colFalsePositive")}</th>
              <th className="num">{t("colIgnored")}</th>
              <th className="num">{t("colPending")}</th>
              <th className="num">{t("colPrecision")}</th>
              <th className="num">{t("colHandling")}</th>
            </tr>
          </thead>
          <tbody>
            {quality.rules.map((row) => (
              <tr key={`${row.family}:${row.key}`}>
                <td className="cell-title">
                  <span className="mono">{row.key}</span> {row.label}
                  <span className="cell-sub">
                    {FAMILY_LABEL[row.family]()}
                    {row.auto_closed > 0 ? ` · ${t("autoClosed", { count: row.auto_closed })}` : ""}
                  </span>
                </td>
                <td className="num mono">{formatNumber(row.signals)}</td>
                <td className="num mono">{formatNumber(row.confirmed)}</td>
                <td className="num mono">{formatNumber(row.false_positive)}</td>
                <td className="num mono">{formatNumber(row.ignored)}</td>
                <td className="num mono">{formatNumber(row.pending)}</td>
                <td className={`num mono${precisionClass(row.precision)}`}>{formatShare(row.precision)}</td>
                <td className="num mono">{formatHours(row.handling_hours_median)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function SourceQuality({ quality }: { quality: AlertQuality }) {
  return (
    <section className="card">
      <h2>{t("qualitySources")}</h2>
      <p className="muted small" style={{ marginTop: 0 }}>
        {t("qualitySourcesNote")}
      </p>
      {quality.sources.length === 0 ? (
        <p className="empty">{t("noSource")}</p>
      ) : (
        <table className="table quality-table" aria-label={t("qualitySources")}>
          <thead>
            <tr>
              <th>{t("colSource")}</th>
              <th className="num">{t("colTriggered")}</th>
              <th className="num">{t("colConfirmed")}</th>
              <th className="num">{t("colExcluded")}</th>
              <th className="num">{t("colPrecision")}</th>
            </tr>
          </thead>
          <tbody>
            {quality.sources.map((src) => (
              <tr key={src.feed_id}>
                <td className="cell-title">
                  {src.name}
                  {src.reliability ? (
                    <span className="cell-sub">
                      {t("colReliability")} {src.reliability}
                    </span>
                  ) : null}
                </td>
                <td className="num mono">{formatNumber(src.triggered)}</td>
                <td className="num mono">{formatNumber(src.confirmed)}</td>
                <td className="num mono">{formatNumber(src.false_positive)}</td>
                <td className={`num mono${precisionClass(src.precision)}`}>{formatShare(src.precision)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

export function Pilotage() {
  // La période est dans l'adresse (?jours=30) : partageable, retrouvée après un rechargement.
  const { search, navigate } = useLocation();
  const days: Period = new URLSearchParams(search).get("jours") === "30" ? 30 : 7;
  const setDays = (value: Period) =>
    navigate(value === 30 ? "/pilotage?jours=30" : "/pilotage", { replace: true });
  const query = useSocMetrics(days);
  const quality = useAlertQuality(days);
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("title")}</h1>
          <p>{t("subtitle")}</p>
        </div>
        <div className="seg" role="group" aria-label={t("period")}>
          {([7, 30] as const).map((value) => (
            <button key={value} type="button" aria-pressed={days === value} onClick={() => setDays(value)}>
              {t("days", { count: value })}
            </button>
          ))}
        </div>
      </div>
      <QueryState query={query}>
        {(metrics) => (
          <>
            <div className="grid kpis">
              <Kpi
                label="MTTA"
                value={formatHours(metrics.mtta_minutes === null ? null : metrics.mtta_minutes / 60)}
                context={t("mttaContext")}
              />
              <Kpi
                label="MTTR"
                value={formatHours(metrics.mttr_hours)}
                context={t("mttrContext", { median: formatHours(metrics.median_ttr_hours), closed: metrics.closed })}
              />
              <Kpi
                label={t("inProgress")}
                value={formatNumber(metrics.open_now)}
                context={t("breachCount", { count: metrics.breaches.length })}
                alert={metrics.breaches.length > 0}
              />
              <Kpi
                label={t("falsePositives")}
                value={formatNumber(metrics.exclusions + metrics.false_positive_events)}
                context={t("fpContext", { iocs: metrics.exclusions, events: metrics.false_positive_events })}
              />
            </div>
            <div className="page-grid" style={{ marginTop: 16 }}>
              <div className="grid">
                <Severities metrics={metrics} />
                <QueryState query={quality}>{(q) => <Quality quality={q} />}</QueryState>
                <QueryState query={quality}>{(q) => <SourceQuality quality={q} />}</QueryState>
                <Breaches metrics={metrics} />
                <Daily metrics={metrics} />
              </div>
              <aside className="grid">
                <Tiers metrics={metrics} />
                <Workload metrics={metrics} />
              </aside>
            </div>
            <p className="muted small">
              {t("footer", { days: metrics.window_days, opened: metrics.opened, critical: levelLabel("CRITICAL") })}
            </p>
          </>
        )}
      </QueryState>
    </>
  );
}
