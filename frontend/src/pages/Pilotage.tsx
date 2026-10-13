// Pilotage SOC (M9, ADR-022) : délais de prise en charge (MTTA) et de résolution (MTTR),
// respect des délais cibles par sévérité, incidents en dépassement, niveaux L1/L2/L3,
// escalades, charge par analyste et activité jour par jour, sur 7 ou 30 jours.
import { useSocMetrics } from "../api/queries";
import type { SocMetrics } from "../api/types";
import { LevelBadge } from "../components/Badge";
import { Kpi } from "../components/Kpi";
import { QueryState } from "../components/QueryState";
import { formatDay, formatHours, formatNumber, formatShare, parseDate } from "../lib/format";
import { CHART, TIER_LABEL, TONE_COLORS, levelLabel } from "../lib/levels";
import { Link, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";

type Period = 7 | 30;

function Severities({ metrics }: { metrics: SocMetrics }) {
  return (
    <section className="card">
      <h2>Délais cibles par sévérité</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Prise en charge : premier geste d'un analyste (assignation, statut, escalade, action, chasse). Résolution :
        ouverture → clôture.
      </p>
      <table className="table sla-table" aria-label="Délais par sévérité">
        <thead>
          <tr>
            <th>Sévérité</th>
            <th className="num">Ouverts</th>
            <th className="num">MTTA</th>
            <th className="num">Cible</th>
            <th className="num">Dans le délai</th>
            <th className="num">Clos</th>
            <th className="num">MTTR</th>
            <th className="num">Cible</th>
            <th className="num">Dans le délai</th>
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
      <h2>En dépassement ({formatNumber(metrics.breaches.length)})</h2>
      {metrics.breaches.length === 0 ? (
        <p className="empty">Aucun incident ouvert hors de ses délais cibles.</p>
      ) : (
        <ul className="list">
          {metrics.breaches.map((b) => (
            <li key={b.incident_id}>
              <LevelBadge level={b.severity} />
              <span className="badge tier">{b.tier}</span>
              <span className="grow">
                <Link to={`/incidents/${b.incident_id}`}>{b.title}</Link>
                <span className="cell-sub">
                  {" "}
                  · {b.kind} : {formatHours(b.age_hours)} pour une cible de {formatHours(b.target_hours)}
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
      <h2>Niveaux SOC</h2>
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
        Incidents en cours par niveau. Escalades sur la période :{" "}
        {steps.length ? steps.map(([step, n]) => `${step} × ${n}`).join(" · ") : "aucune"}.
      </p>
    </section>
  );
}

function Workload({ metrics }: { metrics: SocMetrics }) {
  return (
    <section className="card">
      <h2>Charge par analyste</h2>
      {metrics.workload.length === 0 ? (
        <p className="empty">Aucun incident sur la période.</p>
      ) : (
        <table className="table" aria-label="Charge par analyste">
          <thead>
            <tr>
              <th>Analyste</th>
              <th className="num">En cours</th>
              <th className="num">Clos sur la période</th>
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
      <h2>Ouverts et clos par jour</h2>
      {metrics.daily.map((d) => {
        const day = parseDate(`${d.day}T12:00:00Z`);
        return (
          <div className="bar-row" key={d.day}>
            <span className="muted mono">{day ? formatDay(day, utc) : d.day}</span>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `${(d.opened / max) * 100}%`, background: TONE_COLORS.p1 }} />
            </div>
            <span className="num mono" title="ouverts / clos">
              {d.opened} / {d.closed}
            </span>
          </div>
        );
      })}
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
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Pilotage SOC</h1>
          <p>Délais de prise en charge et de résolution, délais cibles, niveaux et charge</p>
        </div>
        <div className="seg" role="group" aria-label="Période">
          {([7, 30] as const).map((value) => (
            <button key={value} type="button" aria-pressed={days === value} onClick={() => setDays(value)}>
              {value} jours
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
                context="ouverture → prise en charge"
              />
              <Kpi
                label="MTTR"
                value={formatHours(metrics.mttr_hours)}
                context={`médiane ${formatHours(metrics.median_ttr_hours)} · ${formatNumber(metrics.closed)} clos`}
              />
              <Kpi
                label="En cours"
                value={formatNumber(metrics.open_now)}
                context={`${formatNumber(metrics.breaches.length)} en dépassement`}
                alert={metrics.breaches.length > 0}
              />
              <Kpi
                label="Faux positifs écartés"
                value={formatNumber(metrics.exclusions + metrics.false_positive_events)}
                context={`${formatNumber(metrics.exclusions)} IOC exclus · ${formatNumber(metrics.false_positive_events)} corrélations`}
              />
            </div>
            <div className="page-grid" style={{ marginTop: 16 }}>
              <div className="grid">
                <Severities metrics={metrics} />
                <Breaches metrics={metrics} />
                <Daily metrics={metrics} />
              </div>
              <aside className="grid">
                <Tiers metrics={metrics} />
                <Workload metrics={metrics} />
              </aside>
            </div>
            <p className="muted small">
              Sur {metrics.window_days} jours · {formatNumber(metrics.opened)} incident(s) ouvert(s) ·{" "}
              {levelLabel("CRITICAL")} : prise en charge en 1 h, résolution en 24 h.
            </p>
          </>
        )}
      </QueryState>
    </>
  );
}
