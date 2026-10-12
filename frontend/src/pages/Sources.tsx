// Sources CTI : santé de la collecte de chaque source, journal des collectes, réglages
// (ADMIN). La source choisie est dans l'adresse (?source=…). La santé d'une source dit si sa
// collecte fonctionne, jamais si ses IOC sont dangereux.
import { Plus, Power, Trash2 } from "lucide-react";
import { useEffect, useState, type FormEvent, type KeyboardEvent } from "react";

import { useCreateFeed, useDeleteFeed, useUpdateFeed } from "../api/mutations";
import { useFeed, useFeedRuns, useFeedsHealth } from "../api/queries";
import type { CollectionRun, FeedHealth } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { RELIABILITY } from "../components/Confidence";
import { QueryState } from "../components/QueryState";
import { formatAgo, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { POLLING_CHOICES, formatDuration, formatMs, successRate } from "../lib/ops";
import { asUuid, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";

const STATUS: Record<string, [string, string]> = {
  HEALTHY: ["Saine", "ok"],
  DEGRADED: ["Dégradée", "p0"],
  PENDING: ["En attente", "p3"],
};

const FEED_TYPES = ["JSON", "CSV", "STIX", "OTX", "TAXII"];

function StatusBadge({ health }: { health: Pick<FeedHealth, "status" | "is_active"> }) {
  if (!health.is_active) return <span className="badge p3">Suspendue</span>;
  const [label, tone] = STATUS[health.status] ?? [health.status, "p3"];
  return <span className={`badge ${tone}`}>{label}</span>;
}

// --- Résumé --------------------------------------------------------------------------------

function Summary({ feeds }: { feeds: FeedHealth[] }) {
  const active = feeds.filter((f) => f.is_active);
  const healthy = active.filter((f) => f.status === "HEALTHY").length;
  const degraded = active.filter((f) => f.status === "DEGRADED").length;
  const runs = active.reduce((n, f) => n + f.runs_7d, 0);
  const errors = active.reduce((n, f) => n + f.errors_7d, 0);
  const rate = successRate(runs, errors);
  const items: [string, string, string][] = [
    ["Sources actives", formatNumber(active.length), `sur ${formatNumber(feeds.length)} déclarées`],
    ["Saines", formatNumber(healthy), degraded ? `${formatNumber(degraded)} dégradée${degraded > 1 ? "s" : ""}` : "aucune dégradée"],
    ["Collectes sur 7 jours", formatNumber(runs), rate === null ? "aucune collecte" : `${rate}\u202f% réussies`],
  ];
  return (
    <div className="stat-strip">
      {items.map(([label, value, context]) => (
        <div key={label} className="stat">
          <span className="stat-label">{label}</span>
          <span className="stat-value">{value}</span>
          <span className={`stat-context${label === "Saines" && degraded ? " alert" : ""}`}>{context}</span>
        </div>
      ))}
    </div>
  );
}

// --- Liste ---------------------------------------------------------------------------------

function SourceTable({
  feeds,
  selectedId,
  onSelect,
}: {
  feeds: FeedHealth[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  function onKey(event: KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(feeds[index].feed_id);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = feeds[index + (event.key === "ArrowDown" ? 1 : -1)];
      if (next) {
        onSelect(next.feed_id);
        document.getElementById(`source-${next.feed_id}`)?.focus();
      }
    }
  }

  return (
    <table className="table selectable" aria-label="Sources de renseignement">
      <thead>
        <tr>
          <th>Source</th>
          <th>État</th>
          <th>Dernier succès</th>
          <th className="num">Nouveaux</th>
          <th className="num">Réussite 7 j</th>
        </tr>
      </thead>
      <tbody>
        {feeds.map((feed, index) => {
          const success = parseDate(feed.last_successful_run);
          const rate = successRate(feed.runs_7d, feed.errors_7d);
          return (
            <tr
              key={feed.feed_id}
              id={`source-${feed.feed_id}`}
              tabIndex={0}
              aria-current={feed.feed_id === selectedId ? "true" : undefined}
              className={feed.is_active ? undefined : "done"}
              onClick={() => onSelect(feed.feed_id)}
              onKeyDown={(event) => onKey(event, index)}
            >
              <td className="wrap">
                <div className="cell-title">{feed.name}</div>
                <div className="cell-sub">
                  {feed.feed_type}, fiabilité {feed.reliability}
                </div>
              </td>
              <td>
                <StatusBadge health={feed} />
              </td>
              <td className="muted">{success ? `${formatAgo(success)}` : "jamais"}</td>
              <td className="num mono">{feed.last_inserted === null ? "—" : formatNumber(feed.last_inserted)}</td>
              <td className={`num mono${rate !== null && rate < 80 ? " error-text" : ""}`}>
                {rate === null ? "—" : `${rate}\u202f%`}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// --- Fiche d'une source --------------------------------------------------------------------

function RunStrip({ runs }: { runs: CollectionRun[] }) {
  // Les plus anciennes à gauche : la bande se lit comme une frise.
  const ordered = [...runs].reverse();
  return (
    <div className="run-strip" role="img" aria-label={`${runs.filter((r) => !r.succeeded).length} échec(s) sur les ${runs.length} dernières collectes`}>
      {ordered.map((run) => (
        <span key={run.id} className={`run-cell ${run.succeeded ? "ok" : "ko"}`} title={run.started_at} />
      ))}
    </div>
  );
}

function AdminControls({
  feedId,
  active,
  interval,
  reliability,
}: {
  feedId: string;
  active: boolean;
  interval: number;
  reliability: string;
}) {
  const update = useUpdateFeed(feedId);
  const remove = useDeleteFeed();
  const { navigate } = useLocation();
  const [confirming, setConfirming] = useState(false);
  useEffect(() => setConfirming(false), [feedId]);
  const choices = POLLING_CHOICES.includes(interval) ? POLLING_CHOICES : [...POLLING_CHOICES, interval].sort((a, b) => a - b);
  const error = update.error ?? remove.error;

  return (
    <div className="form">
      <label className="field">
        Fréquence de collecte
        <select
          value={interval}
          disabled={update.isPending}
          onChange={(e) => update.mutate({ polling_interval: Number(e.target.value) })}
        >
          {choices.map((seconds) => (
            <option key={seconds} value={seconds}>
              toutes les {formatDuration(seconds)}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        Fiabilité de la source (pondère la confiance de ses IOC)
        <select
          value={reliability}
          disabled={update.isPending}
          onChange={(e) => update.mutate({ reliability: e.target.value })}
        >
          {RELIABILITY.map(([code, label]) => (
            <option key={code} value={code}>
              {label}
            </option>
          ))}
        </select>
      </label>
      {error && (
        <p className="notice error" role="alert">
          Modification refusée : {error.message}
        </p>
      )}
      <div className="actions">
        {confirming ? (
          <>
            <button className="btn quiet" type="button" onClick={() => setConfirming(false)}>
              Annuler
            </button>
            <button
              className="btn danger"
              type="button"
              disabled={remove.isPending}
              onClick={() => remove.mutate(feedId, { onSuccess: () => navigate("/sources", { replace: true }) })}
            >
              <Trash2 size={16} aria-hidden="true" />
              Supprimer définitivement
            </button>
          </>
        ) : (
          <>
            <button className="btn quiet" type="button" onClick={() => setConfirming(true)}>
              <Trash2 size={16} aria-hidden="true" />
              Supprimer
            </button>
            <button
              className={`btn${active ? "" : " primary"}`}
              type="button"
              disabled={update.isPending}
              onClick={() => update.mutate({ is_active: !active })}
            >
              <Power size={16} aria-hidden="true" />
              {active ? "Suspendre la collecte" : "Reprendre la collecte"}
            </button>
          </>
        )}
      </div>
      {confirming && (
        <p className="reason">Les IOC déjà collectés sont conservés, sans rattachement à cette source.</p>
      )}
    </div>
  );
}

function SourcePanel({ health, isAdmin }: { health: FeedHealth; isAdmin: boolean }) {
  const { utc } = useTimeZone();
  const feed = useFeed(health.feed_id);
  const runs = useFeedRuns(health.feed_id);
  const attempt = parseDate(health.last_attempt_at);
  const success = parseDate(health.last_successful_run);
  const rate = successRate(health.runs_7d, health.errors_7d);

  return (
    <aside className="card detail" aria-label={`Source ${health.name}`}>
      <section>
        <div className="title">
          <span className="ellipsis">{health.name}</span>
          <StatusBadge health={health} />
        </div>
        {feed.data && (
          <p className="value-box mono" title="Adresse de collecte">
            {feed.data.url}
          </p>
        )}
      </section>

      <section>
        <h3>Collecte</h3>
        <dl className="facts">
          <dt>Format</dt>
          <dd>{health.feed_type}</dd>
          <dt>Fiabilité</dt>
          <dd>{RELIABILITY.find(([code]) => code === health.reliability)?.[1] ?? health.reliability}</dd>
          <dt>Fréquence</dt>
          <dd>{feed.data ? `toutes les ${formatDuration(feed.data.polling_interval)}` : "…"}</dd>
          <dt>Dernier essai</dt>
          <dd>{attempt ? `${formatDateTime(attempt, utc)}, ${formatAgo(attempt)}` : "jamais"}</dd>
          <dt>Dernier succès</dt>
          <dd>{success ? `${formatDateTime(success, utc)}, ${formatAgo(success)}` : "jamais"}</dd>
          <dt>Durée</dt>
          <dd className="mono">{health.last_duration_ms === null ? "—" : formatMs(health.last_duration_ms)}</dd>
          <dt>Dernière récolte</dt>
          <dd>
            {health.last_inserted === null
              ? "—"
              : `${formatNumber(health.last_inserted)} nouveaux, ${formatNumber(health.last_updated ?? 0)} mis à jour, ${formatNumber(health.last_rejected ?? 0)} rejetés`}
          </dd>
          <dt>Sur 7 jours</dt>
          <dd>
            {formatNumber(health.runs_7d)} collectes, {formatNumber(health.errors_7d)} en échec
            {rate === null ? "" : ` (${rate}\u202f% réussies)`}
          </dd>
        </dl>
        {health.last_error && (
          <p className="notice error" role="status">
            {health.last_error}
          </p>
        )}
      </section>

      <section>
        <h3>Dernières collectes</h3>
        <QueryState query={runs} empty={(items) => items.length === 0}>
          {(items) => (
            <>
              <RunStrip runs={items} />
              <ul className="list">
                {items.slice(0, 8).map((run) => {
                  const at = parseDate(run.started_at);
                  return (
                    <li key={run.id}>
                      <span className={`run-dot ${run.succeeded ? "ok" : "ko"}`} aria-hidden="true" />
                      <span className="mono muted">{at ? formatDateTime(at, utc) : "—"}</span>
                      <span className="grow ellipsis">
                        {run.succeeded
                          ? `${formatNumber(run.inserted)} nouveaux, ${formatNumber(run.updated)} mis à jour${run.rejected ? `, ${formatNumber(run.rejected)} rejetés` : ""}`
                          : (run.error ?? "Échec")}
                      </span>
                      <span className="mono muted">{formatMs(run.duration_ms)}</span>
                    </li>
                  );
                })}
              </ul>
            </>
          )}
        </QueryState>
      </section>

      {isAdmin && (
        <section>
          <h3>Réglages</h3>
          {feed.data ? (
            <AdminControls
              feedId={health.feed_id}
              active={feed.data.is_active}
              interval={feed.data.polling_interval}
              reliability={feed.data.reliability}
            />
          ) : (
            <p className="muted">Chargement…</p>
          )}
        </section>
      )}
    </aside>
  );
}

// --- Ajout d'une source (ADMIN) ------------------------------------------------------------

function NewSource({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const create = useCreateFeed();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("https://");
  const [feedType, setFeedType] = useState("JSON");
  const [pollEvery, setPollEvery] = useState(3600);
  const [reliability, setReliability] = useState("C");

  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate(
      { name: name.trim(), url: url.trim(), feed_type: feedType, polling_interval: pollEvery, reliability },
      { onSuccess: (feed) => onCreated(feed.id) },
    );
  }

  return (
    <form className="card form" onSubmit={submit} aria-labelledby="nouvelle-source">
      <h2 id="nouvelle-source">Ajouter une source</h2>
      <div className="row">
        <label className="field grow">
          Nom
          <input required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          Format
          <select value={feedType} onChange={(e) => setFeedType(e.target.value)}>
            {FEED_TYPES.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Fréquence
          <select value={pollEvery} onChange={(e) => setPollEvery(Number(e.target.value))}>
            {POLLING_CHOICES.map((seconds) => (
              <option key={seconds} value={seconds}>
                toutes les {formatDuration(seconds)}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="field">
        Fiabilité (échelle de l'Amirauté)
        <select value={reliability} onChange={(e) => setReliability(e.target.value)}>
          {RELIABILITY.map(([code, label]) => (
            <option key={code} value={code}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        Adresse (HTTPS publique ; les adresses internes sont refusées)
        <input className="mono" required type="url" maxLength={500} value={url} onChange={(e) => setUrl(e.target.value)} />
      </label>
      {create.error && (
        <p className="notice error" role="alert">
          Source refusée : {create.error.message}
        </p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          Annuler
        </button>
        <button className="btn primary" type="submit" disabled={create.isPending}>
          {create.isPending ? "Ajout…" : "Ajouter la source"}
        </button>
      </div>
    </form>
  );
}

// --- Page ----------------------------------------------------------------------------------

function byAttention(a: FeedHealth, b: FeedHealth): number {
  const weight = (f: FeedHealth) => (!f.is_active ? 3 : f.status === "DEGRADED" ? 0 : f.status === "PENDING" ? 1 : 2);
  return weight(a) - weight(b) || a.name.localeCompare(b.name, "fr");
}

export function Sources() {
  const { user } = useAuth();
  const isAdmin = user?.role === "ADMIN";
  const { search, navigate } = useLocation();
  const requested = asUuid(new URLSearchParams(search).get("source"));
  const [adding, setAdding] = useState(false);
  const query = useFeedsHealth();
  const feeds = [...(query.data ?? [])].sort(byAttention);
  const selected = feeds.find((f) => f.feed_id === requested) ?? (requested ? undefined : feeds[0]);
  const select = (id: string) => navigate(`/sources?source=${id}`, { replace: true });

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Sources CTI</h1>
          <p>État de la collecte de chaque source de renseignement : les sources en difficulté d'abord</p>
        </div>
        {isAdmin && !adding && (
          <button className="btn primary" type="button" onClick={() => setAdding(true)}>
            <Plus size={16} aria-hidden="true" />
            Ajouter une source
          </button>
        )}
      </div>

      {adding && (
        <div className="stack gap-bottom">
          <NewSource
            onClose={() => setAdding(false)}
            onCreated={(id) => {
              setAdding(false);
              select(id);
            }}
          />
        </div>
      )}

      {query.data && <Summary feeds={query.data} />}

      <div className="split">
        <section className="card flush">
          <QueryState query={query} empty={(items) => items.length === 0}>
            {() => <SourceTable feeds={feeds} selectedId={selected?.feed_id ?? null} onSelect={select} />}
          </QueryState>
        </section>
        {selected ? (
          <SourcePanel key={selected.feed_id} health={selected} isAdmin={isAdmin} />
        ) : (
          <aside className="card detail">
            <p className="empty">
              {query.isPending ? "Chargement…" : "Aucune source déclarée. Lancez `illwatch seed` pour les sources de référence."}
            </p>
          </aside>
        )}
      </div>
    </>
  );
}
