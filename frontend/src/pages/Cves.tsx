// CVE et priorités : vulnérabilités classées par score composite (ADR-001, ADR-014), fiche
// justifiant chaque point du score, alertes et incidents liés. La CVE choisie est dans
// l'adresse (?cve=…), la recherche aussi (?q=…).
import { useEffect, useState, type FormEvent, type KeyboardEvent } from "react";

import { useOpenIncidentForCve } from "../api/mutations";
import {
  CVE_PAGE_SIZE,
  useCveAlerts,
  useCveDetail,
  useCves,
  useLinkedIncidents,
  useSummary,
  type CveFilters,
} from "../api/queries";
import type { Cve, CveDetail, IncidentDetail } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { AttachToIncident } from "../components/AttachToIncident";
import { LevelBadge } from "../components/Badge";
import { Breakdown, formatEpss, formatScore } from "../components/CveScore";
import { Pager } from "../components/Pager";
import { QueryState } from "../components/QueryState";
import { formatAge, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { ALERT_REASON, INCIDENT_STATUS, PRIORITY_ORDER, levelLabel } from "../lib/levels";
import { Link, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { RESPONDER_ROLES } from "./Incidents";

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;

/** Sévérité d'incident proposée pour une priorité de CVE. */
const SEVERITY_FOR: Record<string, string> = {
  P0_CRITIQUE: "CRITICAL",
  P1_ELEVE: "HIGH",
  P2_MOYEN: "MEDIUM",
  P3_FAIBLE: "LOW",
};

function urlFor(params: { cve?: string; q?: string }): string {
  const query = new URLSearchParams();
  if (params.q) query.set("q", params.q);
  if (params.cve) query.set("cve", params.cve);
  const text = query.toString();
  return text ? `/cve?${text}` : "/cve";
}

function Signals({ cve }: { cve: Cve }) {
  const tags: string[] = [];
  if (cve.is_kev) tags.push("KEV");
  if (cve.has_public_exploit) tags.push("Exploit");
  if (cve.has_ransomware_campaign) tags.push("Rançongiciel");
  if (tags.length === 0) return <span className="muted">—</span>;
  return (
    <span className="row tight">
      {tags.map((tag) => (
        <span key={tag} className={`badge ${tag === "KEV" ? "p0" : "p1"}`}>
          {tag}
        </span>
      ))}
    </span>
  );
}

// --- Recherche et filtres -------------------------------------------------------------------

function SearchForm({ initial, onSearch }: { initial: string; onSearch: (value: string) => void }) {
  const [text, setText] = useState(initial);
  useEffect(() => setText(initial), [initial]);

  function submit(event: FormEvent) {
    event.preventDefault();
    onSearch(text.trim());
  }

  return (
    <form className="row grow" role="search" onSubmit={submit}>
      <label className="sr-only" htmlFor="recherche-cve">
        Identifiant ou texte
      </label>
      <input
        id="recherche-cve"
        className="compact grow"
        type="search"
        maxLength={100}
        placeholder="CVE-2024-3400, ou un produit : « fortios », « log4j »…"
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <button className="btn" type="submit">
        Rechercher
      </button>
      {initial && (
        <button
          className="btn quiet"
          type="button"
          onClick={() => {
            setText("");
            onSearch("");
          }}
        >
          Effacer
        </button>
      )}
    </form>
  );
}

function PriorityFilter({
  filters,
  onChange,
}: {
  filters: Omit<CveFilters, "q">;
  onChange: (next: Omit<CveFilters, "q">) => void;
}) {
  const counts = useSummary().data?.cves;
  return (
    <div className="row">
      <div className="seg" role="group" aria-label="Priorité">
        <button
          type="button"
          aria-pressed={!filters.priority}
          onClick={() => onChange({ ...filters, priority: undefined })}
        >
          Toutes
        </button>
        {PRIORITY_ORDER.map((priority) => {
          const count = counts?.by_priority[priority];
          return (
            <button
              key={priority}
              type="button"
              aria-pressed={filters.priority === priority}
              onClick={() => onChange({ ...filters, priority })}
            >
              {levelLabel(priority)}
              {count !== undefined ? ` · ${formatNumber(count)}` : ""}
            </button>
          );
        })}
      </div>
      <label className="check">
        <input
          type="checkbox"
          checked={filters.kevOnly}
          onChange={(e) => onChange({ ...filters, kevOnly: e.target.checked })}
        />
        Exploitées (KEV){counts ? ` · ${formatNumber(counts.kev)}` : ""}
      </label>
    </div>
  );
}

// --- Liste ----------------------------------------------------------------------------------

function CveTable({
  items,
  selectedId,
  onSelect,
}: {
  items: Cve[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  function onKey(event: KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(items[index].id);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = items[index + (event.key === "ArrowDown" ? 1 : -1)];
      if (next) {
        onSelect(next.id);
        document.getElementById(`cve-${next.id}`)?.focus();
      }
    }
  }

  return (
    <table className="table selectable" aria-label="Vulnérabilités">
      <thead>
        <tr>
          <th>Priorité</th>
          <th>CVE</th>
          <th className="num">Score</th>
          <th className="num">CVSS</th>
          <th className="num">EPSS</th>
          <th>Signaux</th>
          <th>Modifiée</th>
        </tr>
      </thead>
      <tbody>
        {items.map((cve, index) => {
          const modified = parseDate(cve.last_modified_date);
          return (
            <tr
              key={cve.id}
              id={`cve-${cve.id}`}
              tabIndex={0}
              aria-current={cve.id === selectedId ? "true" : undefined}
              onClick={() => onSelect(cve.id)}
              onKeyDown={(event) => onKey(event, index)}
            >
              <td>
                <LevelBadge level={cve.priority} />
              </td>
              <td className="mono">{cve.id}</td>
              <td className="num mono">{formatScore(cve.composite_risk_score)}</td>
              <td className="num mono">{formatScore(cve.cvss_score)}</td>
              <td className="num mono">{formatEpss(cve.epss_score)}</td>
              <td>
                <Signals cve={cve} />
              </td>
              <td className="muted">{modified ? `il y a ${formatAge(modified)}` : "—"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// --- Fiche ----------------------------------------------------------------------------------

function OpenIncident({ cve }: { cve: CveDetail }) {
  const open = useOpenIncidentForCve();
  const [created, setCreated] = useState<IncidentDetail | null>(null);
  return (
    <>
      {created && (
        <p className="notice ok" role="status">
          Incident ouvert : <Link to={`/incidents/${created.id}`}>{created.title}</Link>
        </p>
      )}
      {open.error && (
        <p className="notice error" role="alert">
          Ouverture refusée : {open.error.message}
        </p>
      )}
      <div className="actions">
        <button
          className="btn"
          type="button"
          disabled={open.isPending || Boolean(created)}
          onClick={() =>
            open.mutate(
              {
                cveId: cve.id,
                severity: SEVERITY_FOR[cve.priority] ?? "MEDIUM",
                description:
                  `Remédiation de ${cve.id} (priorité ${levelLabel(cve.priority)}, score ` +
                  `${formatScore(cve.composite_risk_score)}/100, délai ${cve.sla_hours} h).\n\n${cve.description}`,
              },
              { onSuccess: setCreated },
            )
          }
        >
          {open.isPending ? "Ouverture…" : "Ouvrir un incident pour cette CVE"}
        </button>
      </div>
    </>
  );
}

function CvePanel({ cveId, canAct }: { cveId: string; canAct: boolean }) {
  const { utc } = useTimeZone();
  const query = useCveDetail(cveId);
  const alerts = useCveAlerts(cveId);
  const linked = useLinkedIncidents({ cveId });

  return (
    <aside className="card detail" aria-label={`Fiche ${cveId}`}>
      <QueryState query={query}>
        {(cve) => {
          const published = parseDate(cve.published_date);
          const modified = parseDate(cve.last_modified_date);
          return (
            <>
              {/* 1. Identité et priorité */}
              <section>
                <div className="title">
                  <LevelBadge level={cve.priority} />
                  <span className="mono">{cve.id}</span>
                </div>
                <p className="muted" style={{ margin: "4px 0 0" }}>
                  Score {formatScore(cve.composite_risk_score)}/100 · remédiation sous{" "}
                  {formatNumber(cve.sla_hours)} h ·{" "}
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    fiche NVD ↗
                  </a>
                </p>
                <p className="description">{cve.description}</p>
              </section>

              {/* 2. Signaux */}
              <section>
                <h3>Signaux</h3>
                <dl className="facts">
                  <dt>CVSS</dt>
                  <dd className="mono">
                    {formatScore(cve.cvss_score)}
                    {cve.cvss_vector ? <span className="muted"> · {cve.cvss_vector}</span> : ""}
                  </dd>
                  <dt>EPSS</dt>
                  <dd className="mono">
                    {formatEpss(cve.epss_score)}
                    {cve.epss_percentile !== null
                      ? ` (centile ${formatEpss(cve.epss_percentile)})`
                      : ""}
                  </dd>
                  <dt>Catalogue KEV</dt>
                  <dd>
                    {cve.is_kev
                      ? `oui, depuis le ${cve.kev_date_added ?? "?"}${cve.kev_due_date ? ` · échéance CISA ${cve.kev_due_date}` : ""}`
                      : "non"}
                  </dd>
                  <dt>Exploit public</dt>
                  <dd>{cve.has_public_exploit ? "oui" : "non connu"}</dd>
                  <dt>Rançongiciels</dt>
                  <dd>{cve.has_ransomware_campaign ? "campagnes connues" : "aucune connue"}</dd>
                  <dt>Publiée</dt>
                  <dd>{published ? formatDateTime(published, utc) : "—"}</dd>
                  <dt>Modifiée</dt>
                  <dd>{modified ? `${formatDateTime(modified, utc)} · il y a ${formatAge(modified)}` : "—"}</dd>
                </dl>
                {cve.kev_required_action && (
                  <p className="muted">Action requise (CISA) : {cve.kev_required_action}</p>
                )}
              </section>

              {/* 3. Score justifié */}
              <section>
                <h3>Décomposition du score</h3>
                <Breakdown cve={cve} />
              </section>

              {/* 4. Historique, alertes, incidents */}
              <section>
                <h3>Historique de priorité</h3>
                {cve.history.length === 0 ? (
                  <p className="muted">Aucun changement enregistré.</p>
                ) : (
                  <ul className="list">
                    {[...cve.history].reverse().slice(0, 8).map((change) => {
                      const at = parseDate(change.changed_at);
                      return (
                        <li key={`${change.changed_at}-${change.new_priority}`}>
                          <span className="mono muted">{at ? formatDateTime(at, utc) : "—"}</span>
                          <span>
                            {change.old_priority ? levelLabel(change.old_priority) : "nouvelle"} →{" "}
                            {levelLabel(change.new_priority)} ({formatScore(change.new_score)}, {change.reason})
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                )}

                <h3 style={{ marginTop: 16 }}>Alertes</h3>
                <QueryState query={alerts}>
                  {(page) =>
                    page.items.length === 0 ? (
                      <p className="muted">Aucune alerte émise.</p>
                    ) : (
                      <ul className="list">
                        {page.items.map((alert) => {
                          const at = parseDate(alert.created_at);
                          return (
                            <li key={alert.id}>
                              <span className="mono muted">{at ? formatDateTime(at, utc) : "—"}</span>
                              <Link to={`/triage?alerte=${alert.id}`}>
                                {ALERT_REASON[alert.reason] ?? alert.reason}
                              </Link>
                              <span className="muted">{alert.acknowledged_at ? "acquittée" : "à traiter"}</span>
                            </li>
                          );
                        })}
                      </ul>
                    )
                  }
                </QueryState>

                <h3 style={{ marginTop: 16 }}>Incidents associés</h3>
                <QueryState query={linked}>
                  {(page) =>
                    page.items.length === 0 ? (
                      <p className="muted">Aucun.</p>
                    ) : (
                      <ul className="list">
                        {page.items.map((incident) => (
                          <li key={incident.id}>
                            <LevelBadge level={incident.severity} />
                            <Link to={`/incidents/${incident.id}`} className="ellipsis" title={incident.title}>
                              {incident.title}
                            </Link>
                            <span className="muted">{INCIDENT_STATUS[incident.status] ?? incident.status}</span>
                          </li>
                        ))}
                      </ul>
                    )
                  }
                </QueryState>
              </section>

              {/* 5. Actions */}
              <section>
                {canAct ? (
                  <>
                    <AttachToIncident target={{ cveId: cve.id }} label="cette CVE" />
                    <OpenIncident cve={cve} />
                  </>
                ) : (
                  <p className="reason">Actions réservées aux rôles analyste et administrateur.</p>
                )}
              </section>
            </>
          );
        }}
      </QueryState>
    </aside>
  );
}

// --- Page -----------------------------------------------------------------------------------

export function Cves() {
  const { user } = useAuth();
  const canAct = user ? RESPONDER_ROLES.has(user.role) : false;
  const { search, navigate } = useLocation();
  const params = new URLSearchParams(search);
  const requested = params.get("cve");
  const searched = params.get("q") ?? "";

  const [filters, setFilters] = useState<Omit<CveFilters, "q">>({ kevOnly: false });
  const [offset, setOffset] = useState(0);
  const query = useCves({ ...filters, q: searched }, offset);
  const items = query.data?.items ?? [];
  // Un identifiant exact saisi ouvre sa fiche même si la liste filtrée ne le contient pas.
  const exact = CVE_ID.test(searched) ? searched.toUpperCase() : null;
  const chosen = requested && CVE_ID.test(requested) ? requested.toUpperCase() : null;
  const selectedId = chosen ?? exact ?? items[0]?.id ?? null;

  const changeFilters = (next: Omit<CveFilters, "q">) => {
    setFilters(next);
    setOffset(0);
  };
  const select = (id: string) => navigate(urlFor({ cve: id, q: searched }), { replace: true });
  const runSearch = (value: string) => {
    setOffset(0);
    navigate(urlFor({ q: value }), { replace: true });
  };

  const total = query.data?.total;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>CVE et priorités</h1>
          <p>Vulnérabilités classées par risque réel : gravité, probabilité et exploitation avérée</p>
        </div>
      </div>

      <div className="split">
        <section className="card">
          <div className="toolbar">
            <SearchForm initial={searched} onSearch={runSearch} />
          </div>
          <div className="toolbar">
            <span className="muted">
              {total === undefined
                ? " "
                : `${formatNumber(total)} CVE${searched ? ` pour « ${searched} »` : ""}`}
            </span>
            <PriorityFilter filters={filters} onChange={changeFilters} />
          </div>
          <QueryState query={query} empty={(page) => page.items.length === 0}>
            {(page) => (
              <>
                <CveTable items={page.items} selectedId={selectedId} onSelect={select} />
                <Pager
                  pageSize={CVE_PAGE_SIZE}
                  offset={offset}
                  shown={page.items.length}
                  total={page.total}
                  busy={query.isPlaceholderData}
                  onOffset={setOffset}
                />
              </>
            )}
          </QueryState>
        </section>

        {selectedId ? (
          <CvePanel key={selectedId} cveId={selectedId} canAct={canAct} />
        ) : (
          <aside className="card detail">
            <p className="empty">
              {query.isPending ? "Chargement…" : "Aucune CVE ne correspond à ces critères."}
            </p>
          </aside>
        )}
      </div>
    </>
  );
}
