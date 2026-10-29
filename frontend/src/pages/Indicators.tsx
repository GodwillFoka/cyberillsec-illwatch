// Indicateurs (IOC) : recherche dans la base, provenance de chaque indicateur, rattachement
// à un incident et soumission d'un lot (bulletin, liste). L'IOC choisi est dans l'adresse
// (?ioc=…) ; une recherche peut y être aussi (?valeur=…) pour être partagée.
import { useEffect, useState, type FormEvent, type KeyboardEvent } from "react";

import { apiDownload } from "../api/http";
import { useCreateExclusion, useDeleteExclusion, useSubmitIndicators } from "../api/mutations";
import {
  INDICATOR_PAGE_SIZE,
  useFeedsHealth,
  useIndicator,
  useIndicators,
  useLinkedIncidents,
  type IndicatorFilters,
} from "../api/queries";
import type { Indicator, IndicatorDetail, IngestResult } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { AttachToIncident } from "../components/AttachToIncident";
import { LevelBadge } from "../components/Badge";
import { CONFIDENCE_LABEL, ConfidenceMeter } from "../components/Confidence";
import { formatScore } from "../components/CveScore";
import { Pager } from "../components/Pager";
import { QueryState } from "../components/QueryState";
import { currentLocale } from "../i18n/core";
import { messages } from "../i18n/common.i18n";
import { formatAgo, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { MAX_BATCH, countryName, iocTypeLabel, iocTypes, splitBatch } from "../lib/iocs";
import { INCIDENT_STATUS, SEVERITY_ORDER, levelLabel } from "../lib/levels";
import { Link, asUuid, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { useFresh } from "../lib/useFresh";
import { t } from "./Indicators.i18n";
import { RESPONDER_ROLES } from "./Incidents";

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
        {t("searchLabel")}
      </label>
      <input
        id="recherche-ioc"
        className="compact grow mono"
        type="search"
        maxLength={2048}
        placeholder={t("searchPlaceholder")}
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <button className="btn" type="submit">
        {t("search")}
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
          {t("clear")}
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
    ["actifs", t("stateActive")],
    ["expires", t("stateExpired")],
    ["tous", t("stateAll")],
  ];
  return (
    <div className="row">
      <select
        className="compact"
        aria-label={t("type")}
        value={filters.type ?? ""}
        onChange={(e) => onChange({ ...filters, type: e.target.value || undefined })}
      >
        <option value="">{t("allTypes")}</option>
        {iocTypes().map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
      <select
        className="compact"
        aria-label={t("minSeverity")}
        value={filters.minSeverity ?? ""}
        onChange={(e) => onChange({ ...filters, minSeverity: e.target.value || undefined })}
      >
        <option value="">{t("allSeverities")}</option>
        {SEVERITY_ORDER.map((level) => (
          <option key={level} value={level}>
            {level === "CRITICAL" ? levelLabel(level) : t("andAbove", { level: levelLabel(level) })}
          </option>
        ))}
      </select>
      <select
        className="compact"
        aria-label={t("source")}
        value={filters.feedId ?? ""}
        onChange={(e) => onChange({ ...filters, feedId: e.target.value || undefined })}
      >
        <option value="">{t("allSources")}</option>
        {[...feeds]
          .sort((a, b) => a.name.localeCompare(b.name, currentLocale()))
          .map((feed) => (
            <option key={feed.feed_id} value={feed.feed_id}>
              {feed.name}
            </option>
          ))}
      </select>
      <div className="seg" role="group" aria-label={t("validity")}>
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
    <table className="table selectable" aria-label={t("tableLabel")}>
      <thead>
        <tr>
          <th>{t("colSeverity")}</th>
          <th>{t("colType")}</th>
          <th>{t("colValue")}</th>
          <th>{t("colConfidence")}</th>
          <th className="num">{t("colSources")}</th>
          <th>{t("colSeen")}</th>
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
              <td className="mono ellipsis" style={{ maxWidth: 220 }} title={indicator.value}>
                {indicator.value}
              </td>
              <td>
                <ConfidenceMeter value={indicator.confidence} level={indicator.confidence_level} />
              </td>
              <td className="num mono">{formatNumber(indicator.source_count)}</td>
              <td className="muted">
                {seen ? `${formatAgo(seen)}` : "-"}
                {indicator.is_active ? "" : t("expiredSuffix")}
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
      {state === "done" ? t("copied") : state === "failed" ? t("copyFailed") : t("copy")}
    </button>
  );
}

function FalsePositive({ ioc, canAct }: { ioc: IndicatorDetail; canAct: boolean }) {
  const { user } = useAuth();
  const { utc } = useTimeZone();
  const create = useCreateExclusion();
  const remove = useDeleteExclusion();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const exclusion = ioc.exclusion;
  useEffect(() => {
    setOpen(false);
    setReason("");
  }, [ioc.id]);

  if (exclusion) {
    const since = parseDate(exclusion.created_at);
    const until = parseDate(exclusion.expires_at);
    return (
      <section>
        <h3>{t("falsePositive")}</h3>
        <p className="notice" role="status">
          {t("excludedLine", {
            since: since ? t("excludedSince", { at: formatDateTime(since, utc) }) : "",
            until: until ? t("excludedUntil", { at: formatDateTime(until, utc) }) : "",
            reason: exclusion.reason,
          })}
        </p>
        {exclusion.incident_id && (
          <p className="small">
            <Link to={`/incidents/${exclusion.incident_id}`}>{t("establishedBy")}</Link>
          </p>
        )}
        {user?.role === "ADMIN" && (
          <div className="actions">
            <button
              className="btn quiet"
              type="button"
              disabled={remove.isPending}
              onClick={() => remove.mutate(exclusion.id)}
            >
              {remove.isPending ? t("removing") : t("removeExclusion")}
            </button>
          </div>
        )}
        {remove.error && (
          <p className="notice error" role="alert">
            {remove.error.message}
          </p>
        )}
      </section>
    );
  }
  if (!canAct) return null;
  return (
    <section>
      {!open ? (
        <div className="actions">
          <button className="btn quiet" type="button" onClick={() => setOpen(true)}>
            {t("markFalsePositive")}
          </button>
        </div>
      ) : (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate({ value: ioc.value, reason: reason.trim() }, { onSuccess: () => setOpen(false) });
          }}
        >
          <h3>{t("falsePositive")}</h3>
          <label className="field">
            {t("whySafe")}
            <input required minLength={5} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          {create.error && (
            <p className="notice error" role="alert">
              {create.error.message}
            </p>
          )}
          <div className="actions">
            <button className="btn quiet" type="button" onClick={() => setOpen(false)}>
              {t("cancel")}
            </button>
            <button className="btn primary" type="submit" disabled={create.isPending || reason.trim().length < 5}>
              {create.isPending ? t("excluding") : t("exclude")}
            </button>
          </div>
        </form>
      )}
    </section>
  );
}

function IndicatorPanel({ indicatorId, canAct }: { indicatorId: string; canAct: boolean }) {
  const { utc } = useTimeZone();
  const query = useIndicator(indicatorId);
  const linked = useLinkedIncidents({ indicatorId });

  return (
    <aside className="card detail" aria-label={t("panelLabel")}>
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
                  {ioc.exclusion ? (
                    <span className="badge tag">{t("falsePositive")}</span>
                  ) : (
                    !ioc.is_active && <span className="badge p3">{t("expired")}</span>
                  )}
                </div>
                <p className="value-box mono">{ioc.value}</p>
                <div className="actions">
                  <CopyButton value={ioc.value} />
                </div>
              </section>

              <FalsePositive ioc={ioc} canAct={canAct} />

              {/* 2. Statut */}
              <section>
                <h3>{t("status")}</h3>
                <dl className="facts">
                  <dt>{t("firstSeen")}</dt>
                  <dd>{first ? formatDateTime(first, utc) : "-"}</dd>
                  <dt>{t("lastSeen")}</dt>
                  <dd>{last ? `${formatDateTime(last, utc)} · ${formatAgo(last)}` : "-"}</dd>
                  <dt>{t("observations")}</dt>
                  <dd className="mono">{formatNumber(ioc.hit_count)}</dd>
                  <dt>{t("validityLabel")}</dt>
                  <dd>
                    {expires
                      ? t(ioc.is_active ? "expiresOn" : "expiredOn", { at: formatDateTime(expires, utc) })
                      : t("noExpiry")}
                  </dd>
                </dl>
                {ioc.description && <p className="description">{ioc.description}</p>}
              </section>

              {/* Confiance (ADR-017) : chaque point justifié. */}
              <section>
                <h3>{t("confidence")}</h3>
                <div className="row">
                  <ConfidenceMeter value={ioc.confidence} level={ioc.confidence_level} />
                  <span>{CONFIDENCE_LABEL[ioc.confidence_level] ?? ioc.confidence_level}</span>
                </div>
                <dl className="facts" style={{ marginTop: 10 }}>
                  <dt>{t("sourcesReliability")}</dt>
                  <dd className="mono">+{formatScore(ioc.confidence_breakdown.sources)} / 60</dd>
                  <dt>{t("freshness")}</dt>
                  <dd className="mono">+{formatScore(ioc.confidence_breakdown.freshness)} / 30</dd>
                  <dt>{t("recurrence")}</dt>
                  <dd className="mono">+{formatScore(ioc.confidence_breakdown.recurrence)} / 10</dd>
                </dl>
              </section>

              {/* Enrichissement hors ligne (ADR-017, incrément 2) : IP seulement. */}
              {(ioc.type === "IPV4" || ioc.type === "IPV6" || ioc.type === "NETWORK") && (
                <section>
                  <h3>{t("enrichment")}</h3>
                  {ioc.enrichment ? (
                    <>
                      <dl className="facts">
                        <dt>{t("country")}</dt>
                        <dd>{countryName(ioc.enrichment.country)}</dd>
                        <dt>{t("asn")}</dt>
                        <dd>
                          {ioc.enrichment.asn ? (
                            <>
                              <span className="mono">AS{ioc.enrichment.asn}</span>
                              {ioc.enrichment.as_org ? ` · ${ioc.enrichment.as_org}` : ""}
                            </>
                          ) : (
                            t("unknown")
                          )}
                        </dd>
                      </dl>
                      {!ioc.enrichment.public && (
                        <p className="muted small">{t("notRoutable")}</p>
                      )}
                      <p className="muted small">
                        {t("localBase")}
                        <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">
                          IP Geolocation by DB-IP
                        </a>
                      </p>
                    </>
                  ) : (
                    <p className="muted small">
                      {t("noEnrichment")}
                      <span className="mono">illwatch enrich update</span>).
                    </p>
                  )}
                </section>
              )}

              {/* 3. Provenance (ADR-006) */}
              <section>
                <h3>{t("provenance", { count: ioc.sources.length })}</h3>
                {ioc.sources.length === 0 ? (
                  <p className="muted">{t("manual")}</p>
                ) : (
                  <ul className="list">
                    {ioc.sources.map((source) => {
                      const seen = parseDate(source.last_seen);
                      return (
                        <li key={source.feed_id}>
                          <span className="reliability" title={t("reliabilityTitle")}>
                            {source.reliability}
                          </span>
                          <span className="grow ellipsis">{source.feed_name}</span>
                          <span className="muted">
                            {t.plural("hits", source.hit_count)}
                            {seen ? ` · ${formatAgo(seen)}` : ""}
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </section>

              {/* 4. Incidents associés */}
              <section>
                <h3>{t("linkedIncidents")}</h3>
                <QueryState query={linked}>
                  {(page) =>
                    page.items.length === 0 ? (
                      <p className="muted">{t("none")}</p>
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
                          <li className="muted">{t("andOthers", { count: page.total - page.items.length })}</li>
                        )}
                      </ul>
                    )
                  }
                </QueryState>
              </section>

              {/* 5. Actions */}
              <section>
                {canAct ? (
                  <AttachToIncident target={{ indicatorId: ioc.id }} label={t("thisIoc")} />
                ) : (
                  <p className="reason">{t("rolesOnly")}</p>
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
      <h2 id="soumettre-ioc">{t("submitTitle")}</h2>
      <label className="field">
        {t("valuesField")}
        <textarea
          className="mono"
          rows={8}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={"198.51.100.7\nevil[.]example.com\nhxxps://phish.example/login"}
        />
      </label>
      <p className="muted" aria-live="polite">
        {batch.values.length === 0 ? t("noValue") : t.plural("toSend", batch.values.length)}
        {batch.duplicates > 0 ? t.plural("duplicates", batch.duplicates) : ""}
        {batch.overflow > 0 ? t("overflow", { count: batch.overflow, max: MAX_BATCH }) : ""}
      </p>
      <div className="row">
        <label className="field">
          {t("severity")}
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITY_ORDER.map((level) => (
              <option key={level} value={level}>
                {levelLabel(level)}
              </option>
            ))}
          </select>
        </label>
        <label className="field grow">
          {t("context")}
          <input maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
      </div>
      {submit.error && (
        <p className="notice error" role="alert">
          {t("submitRefused", { message: submit.error.message })}
        </p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          {t("close")}
        </button>
        <button
          className="btn primary"
          type="submit"
          disabled={batch.values.length === 0 || submit.isPending}
        >
          {submit.isPending ? t("sending") : t("submit")}
        </button>
      </div>
    </form>
  );
}

function IngestReport({ result, onClose }: { result: IngestResult; onClose: () => void }) {
  return (
    <section className="card" aria-label={t("reportLabel")}>
      <p className={`notice ${result.rejected_count > 0 ? "" : "ok"}`} role="status">
        {t.plural("received", result.received)}
        {t.plural("inserted", result.inserted)}
        {t("updated", { count: result.updated })}
        {result.duplicates_in_batch > 0 ? t("inBatch", { count: result.duplicates_in_batch }) : ""}
        {result.rejected_count > 0 ? t.plural("rejected", result.rejected_count) : ""}.
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
        <p className="muted">{t("otherRejects", { count: result.rejected_count - result.rejected.length })}</p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          {t("close")}
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
      setState({ busy: false, message: t("exported", { name }), error: false });
    } catch (error) {
      setState({ busy: false, message: t("exportFailed", { message: (error as Error).message }), error: true });
    }
  }
  return (
    <div className="export">
      <button
        className="btn"
        type="button"
        disabled={state.busy}
        title={t("exportHint")}
        onClick={() => void run()}
      >
        {state.busy ? t("exporting") : t("export")}
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
          <h1>{t("title")}</h1>
          <p>{t("subtitle")}</p>
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
              {t("submitTitle")}
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
                    ? t("unknownValue")
                    : t.plural("matches", total)
                  : t.plural(
                      filters.state === "actifs" ? "countActive" : filters.state === "expires" ? "countExpired" : "countAll",
                      total,
                    )}
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
              {query.isPending ? messages("loading") : t("noMatch")}
            </p>
          </aside>
        )}
      </div>
    </>
  );
}
