// Sources CTI : santé de la collecte de chaque source, journal des collectes, réglages
// (ADMIN). La source choisie est dans l'adresse (?source=…). La santé d'une source dit si sa
// collecte fonctionne, jamais si ses IOC sont dangereux.
import { Plus, Power, Trash2 } from "lucide-react";
import { useEffect, useState, type FormEvent, type KeyboardEvent } from "react";

import { useCreateFeed, useDeleteFeed, useUpdateFeed } from "../api/mutations";
import { useFeed, useFeedRuns, useFeedsHealth } from "../api/queries";
import type { CollectionRun, FeedHealth } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { reliabilityScale } from "../components/Confidence";
import { QueryState } from "../components/QueryState";
import { currentLocale } from "../i18n/core";
import { messages } from "../i18n/common.i18n";
import { formatAgo, formatDateTime, formatNumber, formatShare, parseDate } from "../lib/format";
import { POLLING_CHOICES, formatDuration, formatMs, successRate } from "../lib/ops";
import { asUuid, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { t } from "./Sources.i18n";

const STATUS_TONE: Record<string, string> = { HEALTHY: "ok", DEGRADED: "p0", PENDING: "p3" };

/** Taux entier (0–100) en pourcentage de la langue : « 83 % », « 83% ». */
const percent = (rate: number) => formatShare(rate / 100);

const FEED_TYPES = ["JSON", "CSV", "STIX", "OTX", "TAXII"];

function StatusBadge({ health }: { health: Pick<FeedHealth, "status" | "is_active"> }) {
  if (!health.is_active) return <span className="badge p3">{t("suspended")}</span>;
  const tone = STATUS_TONE[health.status] ?? "p3";
  const label =
    health.status in STATUS_TONE ? t(`status.${health.status}` as Parameters<typeof t>[0]) : health.status;
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
  const items: [string, string, string, boolean][] = [
    [t("activeSources"), formatNumber(active.length), t("ofDeclared", { count: feeds.length }), false],
    [t("healthy"), formatNumber(healthy), degraded ? t.plural("degraded", degraded) : t("noneDegraded"), degraded > 0],
    [t("runs7d"), formatNumber(runs), rate === null ? t("noRun") : t("succeeded", { rate: percent(rate) }), false],
  ];
  return (
    <div className="stat-strip">
      {items.map(([label, value, context, alert]) => (
        <div key={label} className="stat">
          <span className="stat-label">{label}</span>
          <span className="stat-value">{value}</span>
          <span className={`stat-context${alert ? " alert" : ""}`}>{context}</span>
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
    <table className="table selectable" aria-label={t("tableLabel")}>
      <thead>
        <tr>
          <th>{t("colSource")}</th>
          <th>{t("colState")}</th>
          <th>{t("colLastSuccess")}</th>
          <th className="num">{t("colNew")}</th>
          <th className="num">{t("colSuccess7d")}</th>
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
                  {t("typeReliability", { type: feed.feed_type, reliability: feed.reliability })}
                </div>
              </td>
              <td>
                <StatusBadge health={feed} />
              </td>
              <td className="muted">{success ? formatAgo(success) : t("never")}</td>
              <td className="num mono">{feed.last_inserted === null ? "—" : formatNumber(feed.last_inserted)}</td>
              <td className={`num mono${rate !== null && rate < 80 ? " error-text" : ""}`}>
                {rate === null ? "—" : percent(rate)}
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
    <div className="run-strip" role="img" aria-label={t("runStrip", { failed: runs.filter((r) => !r.succeeded).length, total: runs.length })}>
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
        {t("frequency")}
        <select
          value={interval}
          disabled={update.isPending}
          onChange={(e) => update.mutate({ polling_interval: Number(e.target.value) })}
        >
          {choices.map((seconds) => (
            <option key={seconds} value={seconds}>
              {t("every", { duration: formatDuration(seconds) })}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        {t("reliabilityField")}
        <select
          value={reliability}
          disabled={update.isPending}
          onChange={(e) => update.mutate({ reliability: e.target.value })}
        >
          {reliabilityScale().map(([code, label]) => (
            <option key={code} value={code}>
              {label}
            </option>
          ))}
        </select>
      </label>
      {error && (
        <p className="notice error" role="alert">
          {t("changeRefused", { message: error.message })}
        </p>
      )}
      <div className="actions">
        {confirming ? (
          <>
            <button className="btn quiet" type="button" onClick={() => setConfirming(false)}>
              {t("cancel")}
            </button>
            <button
              className="btn danger"
              type="button"
              disabled={remove.isPending}
              onClick={() => remove.mutate(feedId, { onSuccess: () => navigate("/sources", { replace: true }) })}
            >
              <Trash2 size={16} aria-hidden="true" />
              {t("deleteForever")}
            </button>
          </>
        ) : (
          <>
            <button className="btn quiet" type="button" onClick={() => setConfirming(true)}>
              <Trash2 size={16} aria-hidden="true" />
              {t("delete")}
            </button>
            <button
              className={`btn${active ? "" : " primary"}`}
              type="button"
              disabled={update.isPending}
              onClick={() => update.mutate({ is_active: !active })}
            >
              <Power size={16} aria-hidden="true" />
              {active ? t("suspend") : t("resume")}
            </button>
          </>
        )}
      </div>
      {confirming && (
        <p className="reason">{t("deleteNote")}</p>
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
    <aside className="card detail" aria-label={t("panelLabel", { name: health.name })}>
      <section>
        <div className="title">
          <span className="ellipsis">{health.name}</span>
          <StatusBadge health={health} />
        </div>
        {feed.data && (
          <p className="value-box mono" title={t("collectUrl")}>
            {feed.data.url}
          </p>
        )}
      </section>

      <section>
        <h3>{t("collection")}</h3>
        <dl className="facts">
          <dt>{t("format")}</dt>
          <dd>{health.feed_type}</dd>
          <dt>{t("reliability")}</dt>
          <dd>{reliabilityScale().find(([code]) => code === health.reliability)?.[1] ?? health.reliability}</dd>
          <dt>{t("frequencyLabel")}</dt>
          <dd>{feed.data ? t("every", { duration: formatDuration(feed.data.polling_interval) }) : "…"}</dd>
          <dt>{t("lastTry")}</dt>
          <dd>{attempt ? `${formatDateTime(attempt, utc)}, ${formatAgo(attempt)}` : t("never")}</dd>
          <dt>{t("lastSuccess")}</dt>
          <dd>{success ? `${formatDateTime(success, utc)}, ${formatAgo(success)}` : t("never")}</dd>
          <dt>{t("duration")}</dt>
          <dd className="mono">{health.last_duration_ms === null ? "—" : formatMs(health.last_duration_ms)}</dd>
          <dt>{t("lastHarvest")}</dt>
          <dd>
            {health.last_inserted === null
              ? "—"
              : t("harvest", {
                  inserted: health.last_inserted,
                  updated: health.last_updated ?? 0,
                  rejected: health.last_rejected ?? 0,
                })}
          </dd>
          <dt>{t("over7d")}</dt>
          <dd>
            {t("runsLine", { runs: health.runs_7d, errors: health.errors_7d })}
            {rate === null ? "" : t("rateSuffix", { rate: percent(rate) })}
          </dd>
        </dl>
        {health.last_error && (
          <p className="notice error" role="status">
            {health.last_error}
          </p>
        )}
      </section>

      <section>
        <h3>{t("recentRuns")}</h3>
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
                          ? `${t("runOk", { inserted: run.inserted, updated: run.updated })}${run.rejected ? t("runRejected", { count: run.rejected }) : ""}`
                          : (run.error ?? t("failed"))}
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
          <h3>{t("settings")}</h3>
          {feed.data ? (
            <AdminControls
              feedId={health.feed_id}
              active={feed.data.is_active}
              interval={feed.data.polling_interval}
              reliability={feed.data.reliability}
            />
          ) : (
            <p className="muted">{messages("loading")}</p>
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
      <h2 id="nouvelle-source">{t("addTitle")}</h2>
      <div className="row">
        <label className="field grow">
          {t("name")}
          <input required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          {t("format")}
          <select value={feedType} onChange={(e) => setFeedType(e.target.value)}>
            {FEED_TYPES.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          {t("frequencyLabel")}
          <select value={pollEvery} onChange={(e) => setPollEvery(Number(e.target.value))}>
            {POLLING_CHOICES.map((seconds) => (
              <option key={seconds} value={seconds}>
                {t("every", { duration: formatDuration(seconds) })}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="field">
        {t("reliabilityAdmiralty")}
        <select value={reliability} onChange={(e) => setReliability(e.target.value)}>
          {reliabilityScale().map(([code, label]) => (
            <option key={code} value={code}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        {t("url")}
        <input className="mono" required type="url" maxLength={500} value={url} onChange={(e) => setUrl(e.target.value)} />
      </label>
      {create.error && (
        <p className="notice error" role="alert">
          {t("refused", { message: create.error.message })}
        </p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          {t("cancel")}
        </button>
        <button className="btn primary" type="submit" disabled={create.isPending}>
          {create.isPending ? t("adding") : t("add")}
        </button>
      </div>
    </form>
  );
}

// --- Page ----------------------------------------------------------------------------------

function byAttention(a: FeedHealth, b: FeedHealth): number {
  const weight = (f: FeedHealth) => (!f.is_active ? 3 : f.status === "DEGRADED" ? 0 : f.status === "PENDING" ? 1 : 2);
  return weight(a) - weight(b) || a.name.localeCompare(b.name, currentLocale());
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
          <h1>{t("title")}</h1>
          <p>{t("subtitle")}</p>
        </div>
        {isAdmin && !adding && (
          <button className="btn primary" type="button" onClick={() => setAdding(true)}>
            <Plus size={16} aria-hidden="true" />
            {t("addTitle")}
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
              {query.isPending ? messages("loading") : t("noSource")}
            </p>
          </aside>
        )}
      </div>
    </>
  );
}
