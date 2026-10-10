// Indicateurs (IOC) : recherche dans la base, provenance de chaque indicateur, rattachement
// à un incident et soumission d'un lot (bulletin, liste). L'IOC choisi est dans l'adresse
// (?ioc=…) ; une recherche peut y être aussi (?valeur=…) pour être partagée.
import { useEffect, useState, type FormEvent, type KeyboardEvent } from "react";

import { apiDownload } from "../api/http";
import { useSubmitIndicators } from "../api/mutations";
import {
  INDICATOR_PAGE_SIZE,
  useFeedsHealth,
  useIndicator,
  useIndicators,
  useLinkedIncidents,
  type IndicatorFilters,
} from "../api/queries";
import type { Indicator, IngestResult } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { AttachToIncident } from "../components/AttachToIncident";
import { LevelBadge } from "../components/Badge";
import { Pager } from "../components/Pager";
import { QueryState } from "../components/QueryState";
import { formatAge, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { IOC_TYPES, MAX_BATCH, iocTypeLabel, splitBatch } from "../lib/iocs";
import { INCIDENT_STATUS, SEVERITY_ORDER, levelLabel } from "../lib/levels";
import { Link, asUuid, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { useFresh } from "../lib/useFresh";
import { RESPONDER_ROLES } from "./Incidents";

const plural = (n: number, word: string) => `${formatNumber(n)} ${word}${n > 1 ? "s" : ""}`;

function urlFor(params: { ioc?: string; valeur?: string }): string {
  const query = new URLSearchParams();
  if (params.valeur) query.set("valeur", params.valeur);
  if (params.ioc) query.set("ioc", params.ioc);
  const text = query.toString();
  return text ? `/indicateurs?${text}` : "/indicateurs";
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
      <label className="sr-only" htmlFor="recherche-ioc">
        Valeur recherchée
      </label>
      <input
        id="recherche-ioc"
        className="compact grow mono"
        type="search"
        maxLength={2048}
        placeholder="IP, domaine, URL, empreinte, e-mail (evil[.]com accepté)"
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

function Filters({
  filters,
  onChange,
}: {
  filters: IndicatorFilters;
  onChange: (next: IndicatorFilters) => void;
}) {
  const feeds = useFeedsHealth().data ?? [];
  const states: [IndicatorFilters["state"], string][] = [
    ["actifs", "Actifs"],
    ["expires", "Expirés"],
    ["tous", "Tous"],
  ];
  return (
    <div className="row">
      <select
        className="compact"
        aria-label="Type"
        value={filters.type ?? ""}
        onChange={(e) => onChange({ ...filters, type: e.target.value || undefined })}
      >
        <option value="">Tous les types</option>
        {IOC_TYPES.map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
      <select
        className="compact"
        aria-label="Sévérité minimale"
        value={filters.minSeverity ?? ""}
        onChange={(e) => onChange({ ...filters, minSeverity: e.target.value || undefined })}
      >
        <option value="">Toutes sévérités</option>
        {SEVERITY_ORDER.map((level) => (
          <option key={level} value={level}>
            {level === "CRITICAL" ? levelLabel(level) : `${levelLabel(level)} et plus`}
          </option>
        ))}
      </select>
      <select
        className="compact"
        aria-label="Source"
        value={filters.feedId ?? ""}
        onChange={(e) => onChange({ ...filters, feedId: e.target.value || undefined })}
      >
        <option value="">Toutes les sources</option>
        {[...feeds]
          .sort((a, b) => a.name.localeCompare(b.name, "fr"))
          .map((feed) => (
            <option key={feed.feed_id} value={feed.feed_id}>
              {feed.name}
            </option>
          ))}
      </select>
      <div className="seg" role="group" aria-label="Validité">
        {states.map(([value, label]) => (
          <button
            key={value}
            type="button"
            aria-pressed={filters.state === value}
            onClick={() => onChange({ ...filters, state: value })}
          >
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}

// --- Liste ----------------------------------------------------------------------------------

function IndicatorTable({
  items,
  selectedId,
  onSelect,
}: {
  items: Indicator[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const fresh = useFresh(items.map((i) => `${i.id}:${i.last_seen}`));

  function onKey(event: KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(items[index].id);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = items[index + (event.key === "ArrowDown" ? 1 : -1)];
      if (next) {
        onSelect(next.id);
        document.getElementById(`ioc-${next.id}`)?.focus();
      }
    }
  }

  return (
    <table className="table selectable" aria-label="Indicateurs de compromission">
      <thead>
        <tr>
          <th>Sévérité</th>
          <th>Type</th>
          <th>Valeur</th>
          <th className="num">Sources</th>
          <th className="num">Observations</th>
          <th>Vu</th>
        </tr>
      </thead>
      <tbody>
        {items.map((indicator, index) => {
          const seen = parseDate(indicator.last_seen);
          const classes = [
            fresh.has(`${indicator.id}:${indicator.last_seen}`) ? "fresh" : "",
            indicator.is_active ? "" : "done",
          ]
            .filter(Boolean)
            .join(" ");
          return (
            <tr
              key={indicator.id}
              id={`ioc-${indicator.id}`}
              tabIndex={0}
              aria-current={indicator.id === selectedId ? "true" : undefined}
              className={classes || undefined}
              onClick={() => onSelect(indicator.id)}
              onKeyDown={(event) => onKey(event, index)}
            >
              <td>
                <LevelBadge level={indicator.severity} />
              </td>
              <td className="muted">{iocTypeLabel(indicator.type)}</td>
              <td className="mono ellipsis" style={{ maxWidth: 360 }} title={indicator.value}>
                {indicator.value}
              </td>
              <td className="num mono">{formatNumber(indicator.source_count)}</td>
              <td className="num mono">{formatNumber(indicator.hit_count)}</td>
              <td className="muted">
                {seen ? `il y a ${formatAge(seen)}` : "—"}
                {indicator.is_active ? "" : " · expiré"}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// --- Détail ---------------------------------------------------------------------------------

function CopyButton({ value }: { value: string }) {
  const [state, setState] = useState<"idle" | "done" | "failed">("idle");
  useEffect(() => setState("idle"), [value]);
  return (
    <button
      className="btn quiet"
      type="button"
      onClick={() => {
        // Le presse-papiers n'est permis qu'en HTTPS ou sur localhost.
        if (!window.isSecureContext || !("clipboard" in navigator)) {
          setState("failed");
          return;
        }
        navigator.clipboard.writeText(value).then(
          () => setState("done"),
          () => setState("failed"),
        );
      }}
    >
      {state === "done" ? "Copié" : state === "failed" ? "Copie impossible" : "Copier"}
    </button>
  );
}

function IndicatorPanel({ indicatorId, canAct }: { indicatorId: string; canAct: boolean }) {
  const { utc } = useTimeZone();
  const query = useIndicator(indicatorId);
  const linked = useLinkedIncidents({ indicatorId });

  return (
    <aside className="card detail" aria-label="Détail de l'indicateur">
      <QueryState query={query}>
        {(ioc) => {
          const first = parseDate(ioc.first_seen);
          const last = parseDate(ioc.last_seen);
          const expires = parseDate(ioc.expires_at);
          return (
            <>
              {/* 1. Identité */}
              <section>
                <div className="title">
                  <LevelBadge level={ioc.severity} />
                  <span>{iocTypeLabel(ioc.type)}</span>
                  {!ioc.is_active && <span className="badge p3">Expiré</span>}
                </div>
                <p className="value-box mono">{ioc.value}</p>
                <div className="actions">
                  <CopyButton value={ioc.value} />
                </div>
              </section>

              {/* 2. Statut */}
              <section>
                <h3>Statut</h3>
                <dl className="facts">
                  <dt>Première observation</dt>
                  <dd>{first ? formatDateTime(first, utc) : "—"}</dd>
                  <dt>Dernière observation</dt>
                  <dd>{last ? `${formatDateTime(last, utc)} · il y a ${formatAge(last)}` : "—"}</dd>
                  <dt>Observations</dt>
                  <dd className="mono">{formatNumber(ioc.hit_count)}</dd>
                  <dt>Validité</dt>
                  <dd>
                    {expires
                      ? `${ioc.is_active ? "expire" : "expiré"} le ${formatDateTime(expires, utc)}`
                      : "sans expiration"}
                  </dd>
                </dl>
                {ioc.description && <p className="description">{ioc.description}</p>}
              </section>

              {/* 3. Provenance (ADR-006) */}
              <section>
                <h3>Provenance ({ioc.sources.length})</h3>
                {ioc.sources.length === 0 ? (
                  <p className="muted">Soumis à la main, sans source rattachée.</p>
                ) : (
                  <ul className="list">
                    {ioc.sources.map((source) => {
                      const seen = parseDate(source.last_seen);
                      return (
                        <li key={source.feed_id}>
                          <span>{source.feed_name}</span>
                          <span className="muted">
                            {plural(source.hit_count, "observation")}
                            {seen ? ` · il y a ${formatAge(seen)}` : ""}
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </section>

              {/* 4. Incidents associés */}
              <section>
                <h3>Incidents associés</h3>
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
                        {page.total > page.items.length && (
                          <li className="muted">… et {formatNumber(page.total - page.items.length)} autres.</li>
                        )}
                      </ul>
                    )
                  }
                </QueryState>
              </section>

              {/* 5. Actions */}
              <section>
                {canAct ? (
                  <AttachToIncident target={{ indicatorId: ioc.id }} label="cet IOC" />
                ) : (
                  <p className="reason">Association réservée aux rôles analyste et administrateur.</p>
                )}
              </section>
            </>
          );
        }}
      </QueryState>
    </aside>
  );
}

// --- Soumission d'un lot --------------------------------------------------------------------

function SubmitForm({ onClose, onDone }: { onClose: () => void; onDone: (result: IngestResult) => void }) {
  const submit = useSubmitIndicators();
  const [text, setText] = useState("");
  const [severity, setSeverity] = useState("MEDIUM");
  const [description, setDescription] = useState("");
  const batch = splitBatch(text);

  function send(event: FormEvent) {
    event.preventDefault();
    if (batch.values.length === 0) return;
    submit.mutate(
      { values: batch.values, severity, description: description.trim() },
      { onSuccess: onDone },
    );
  }

  return (
    <form className="card form" onSubmit={send} aria-labelledby="soumettre-ioc">
      <h2 id="soumettre-ioc">Soumettre des IOC</h2>
      <label className="field">
        Valeurs : une par ligne, ou séparées par des espaces ou des virgules (« # » : commentaire)
        <textarea
          className="mono"
          rows={8}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={"198.51.100.7\nevil[.]example.com\nhxxps://phish.example/login"}
        />
      </label>
      <p className="muted" aria-live="polite">
        {batch.values.length === 0
          ? "Aucune valeur."
          : `${plural(batch.values.length, "valeur")} à envoyer`}
        {batch.duplicates > 0 ? ` · ${plural(batch.duplicates, "doublon")} retiré${batch.duplicates > 1 ? "s" : ""}` : ""}
        {batch.overflow > 0
          ? ` · ${formatNumber(batch.overflow)} au-delà de ${formatNumber(MAX_BATCH)} non envoyées (faire plusieurs lots)`
          : ""}
      </p>
      <div className="row">
        <label className="field">
          Sévérité
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITY_ORDER.map((level) => (
              <option key={level} value={level}>
                {levelLabel(level)}
              </option>
            ))}
          </select>
        </label>
        <label className="field grow">
          Contexte (source du bulletin, campagne) — facultatif
          <input maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
      </div>
      {submit.error && (
        <p className="notice error" role="alert">
          Soumission refusée : {submit.error.message}
        </p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          Fermer
        </button>
        <button
          className="btn primary"
          type="submit"
          disabled={batch.values.length === 0 || submit.isPending}
        >
          {submit.isPending ? "Envoi…" : "Soumettre"}
        </button>
      </div>
    </form>
  );
}

function IngestReport({ result, onClose }: { result: IngestResult; onClose: () => void }) {
  return (
    <section className="card" aria-label="Résultat de la soumission">
      <p className={`notice ${result.rejected_count > 0 ? "" : "ok"}`} role="status">
        {plural(result.received, "valeur")} reçue{result.received > 1 ? "s" : ""} :{" "}
        {plural(result.inserted, "nouvel IOC")}, {formatNumber(result.updated)} mis à jour
        {result.duplicates_in_batch > 0 ? `, ${formatNumber(result.duplicates_in_batch)} en double` : ""}
        {result.rejected_count > 0 ? `, ${formatNumber(result.rejected_count)} rejetée${result.rejected_count > 1 ? "s" : ""}` : ""}.
      </p>
      {result.rejected.length > 0 && (
        <ul className="list">
          {result.rejected.map((reject, index) => (
            <li key={`${reject.value}-${index}`}>
              <span className="mono ellipsis" title={reject.value}>
                {reject.value}
              </span>
              <span className="muted">{reject.reason}</span>
            </li>
          ))}
        </ul>
      )}
      {result.rejected_count > result.rejected.length && (
        <p className="muted">… {formatNumber(result.rejected_count - result.rejected.length)} autres rejets non listés.</p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          Fermer
        </button>
      </div>
    </section>
  );
}

// --- Export ---------------------------------------------------------------------------------

function ExportButton() {
  const [state, setState] = useState<{ busy: boolean; message: string | null; error: boolean }>({
    busy: false,
    message: null,
    error: false,
  });
  async function run() {
    setState({ busy: true, message: null, error: false });
    try {
      const name = await apiDownload("/dashboard/export", { dataset: "iocs", format: "csv" }, "illwatch-iocs.csv");
      setState({ busy: false, message: `${name} enregistré (export consigné au journal d'audit).`, error: false });
    } catch (error) {
      setState({ busy: false, message: `Export impossible : ${(error as Error).message}`, error: true });
    }
  }
  return (
    <div className="export">
      <button
        className="btn"
        type="button"
        disabled={state.busy}
        title="Toute la base d'IOC : plusieurs dizaines de Mo, une quinzaine de secondes"
        onClick={() => void run()}
      >
        {state.busy ? "Export en cours…" : "Exporter la base (CSV)"}
      </button>
      {state.message && (
        <p className={state.error ? "reason error-text" : "reason"} role={state.error ? "alert" : "status"}>
          {state.message}
        </p>
      )}
    </div>
  );
}

// --- Page -----------------------------------------------------------------------------------

export function Indicators() {
  const { user } = useAuth();
  const canAct = user ? RESPONDER_ROLES.has(user.role) : false;
  const { search, navigate } = useLocation();
  const params = new URLSearchParams(search);
  const requested = asUuid(params.get("ioc"));
  const searched = params.get("valeur") ?? "";

  const [filters, setFilters] = useState<IndicatorFilters>({ state: "actifs" });
  const [offset, setOffset] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [report, setReport] = useState<IngestResult | null>(null);

  // Une recherche par valeur porte sur tous les états : un IOC expiré reste une trace utile.
  // Les filtres, masqués pendant la recherche, ne s'y appliquent pas non plus.
  const effective: IndicatorFilters = searched ? { value: searched, state: "tous" } : filters;
  const query = useIndicators(effective, offset);
  const items = query.data?.items ?? [];
  const selectedId = requested ?? items[0]?.id ?? null;

  const changeFilters = (next: IndicatorFilters) => {
    setFilters(next);
    setOffset(0);
  };
  const select = (id: string) => navigate(urlFor({ ioc: id, valeur: searched }), { replace: true });
  const runSearch = (value: string) => {
    setOffset(0);
    navigate(urlFor({ valeur: value }), { replace: true });
  };

  const total = query.data?.total;

  // Nouvelle recherche (ou retour arrière) : première page.
  useEffect(() => setOffset(0), [searched]);
  // La liste a rétréci sous la page affichée (expiration, collecte) : dernière page valide.
  useEffect(() => {
    if (total !== undefined && total > 0 && offset >= total) {
      setOffset(Math.floor((total - 1) / INDICATOR_PAGE_SIZE) * INDICATOR_PAGE_SIZE);
    }
  }, [total, offset]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Indicateurs (IOC)</h1>
          <p>Recherche, provenance et rattachement des indicateurs de compromission</p>
        </div>
        <div className="row">
          <ExportButton />
          {canAct && !submitting && (
            <button
              className="btn primary"
              type="button"
              onClick={() => {
                setReport(null);
                setSubmitting(true);
              }}
            >
              Soumettre des IOC
            </button>
          )}
        </div>
      </div>

      {(submitting || report) && (
        <div className="stack" style={{ marginBottom: 16 }}>
          {submitting && (
            <SubmitForm
              onClose={() => setSubmitting(false)}
              onDone={(result) => {
                setReport(result);
                setSubmitting(false);
              }}
            />
          )}
          {report && <IngestReport result={report} onClose={() => setReport(null)} />}
        </div>
      )}

      <div className="split">
        <section className="card">
          <div className="toolbar">
            <SearchForm initial={searched} onSearch={runSearch} />
          </div>
          <div className="toolbar">
            <span className="muted">
              {total === undefined
                ? " "
                : searched
                  ? total === 0
                    ? "Valeur inconnue de la base (ou invalide)."
                    : `${plural(total, "correspondance")} exacte${total > 1 ? "s" : ""}`
                  : `${plural(total, "indicateur")}${filters.state === "actifs" ? ` actif${total > 1 ? "s" : ""}` : filters.state === "expires" ? ` expiré${total > 1 ? "s" : ""}` : ""}`}
            </span>
            {!searched && <Filters filters={filters} onChange={changeFilters} />}
          </div>
          <QueryState query={query} empty={(page) => page.items.length === 0}>
            {(page) => (
              <>
                <IndicatorTable items={page.items} selectedId={selectedId} onSelect={select} />
                <Pager
                  pageSize={INDICATOR_PAGE_SIZE}
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
          <IndicatorPanel key={selectedId} indicatorId={selectedId} canAct={canAct} />
        ) : (
          <aside className="card detail">
            <p className="empty">
              {query.isPending ? "Chargement…" : "Aucun indicateur ne correspond à ces critères."}
            </p>
          </aside>
        )}
      </div>
    </>
  );
}
