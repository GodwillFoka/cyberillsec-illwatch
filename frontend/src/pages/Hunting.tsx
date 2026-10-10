// Chasse (MOD-06) : lancer une session sur des observables, un inventaire d'actifs ou toute
// la base, puis lire ses correspondances règle par règle. La session choisie est dans
// l'adresse (?session=…).
import { useState, type FormEvent, type KeyboardEvent } from "react";

import { useRunHunt } from "../api/mutations";
import {
  MATCH_PAGE_SIZE,
  useHunt,
  useHuntMatches,
  useHuntRules,
  useHunts,
  type MatchFilters,
} from "../api/queries";
import type { Hunt, HuntRule } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { LevelBadge } from "../components/Badge";
import { Pager } from "../components/Pager";
import { QueryState } from "../components/QueryState";
import { formatAge, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { MAX_HUNT_OBSERVABLES, splitAssets, splitBatch } from "../lib/iocs";
import { SEVERITY_ORDER, levelLabel } from "../lib/levels";
import { Link, asUuid, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { useFresh } from "../lib/useFresh";
import { RESPONDER_ROLES } from "./Incidents";

const STATUS: Record<string, [string, string]> = {
  EN_COURS: ["En cours", "new"],
  TERMINEE: ["Terminée", "ok"],
  PARTIELLE: ["Partielle", "p1"],
  ECHEC: ["Échec", "p0"],
};

/** Règles qui n'examinent que l'inventaire (ASSET_ONLY_RULES côté serveur). */
const ASSET_ONLY_RULES = new Set(["RULE-05"]);

const TRIGGER: Record<string, string> = { MANUAL: "Manuelle", SCHEDULED: "Planifiée" };

const plural = (n: number, word: string) => `${formatNumber(n)} ${word}${n > 1 ? "s" : ""}`;

function StatusBadge({ status }: { status: string }) {
  const [label, tone] = STATUS[status] ?? [status, "p3"];
  return <span className={`badge ${tone}`}>{label}</span>;
}

function durationOf(hunt: Hunt): string {
  const start = parseDate(hunt.started_at);
  const end = parseDate(hunt.finished_at);
  if (!start || !end) return "—";
  const ms = end.getTime() - start.getTime();
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1).replace(".", ",")} s`;
}

// --- Nouvelle session -----------------------------------------------------------------------

function NewHunt({
  rules,
  onClose,
  onDone,
}: {
  rules: HuntRule[];
  onClose: () => void;
  onDone: (huntId: string) => void;
}) {
  const run = useRunHunt();
  const [text, setText] = useState("");
  const [assetsText, setAssetsText] = useState("");
  const [selected, setSelected] = useState<Set<string>>(() => new Set(rules.map((r) => r.id)));
  const batch = splitBatch(text, MAX_HUNT_OBSERVABLES);
  const assets = splitAssets(assetsText);
  const assetOnly = [...selected].every((id) => ASSET_ONLY_RULES.has(id));
  // Sans observable, la chasse lit toute la base d'IOC actifs : seulement sur confirmation.
  const wholeBase = batch.values.length === 0 && !assetOnly;
  const [confirmed, setConfirmed] = useState(false);
  const ready = selected.size > 0 && (!wholeBase || confirmed) && !(assetOnly && assets.length === 0 && batch.values.length === 0);

  function toggle(id: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready) return;
    run.mutate(
      {
        observables: batch.values,
        assets,
        rules: rules.filter((r) => selected.has(r.id)).map((r) => r.id),
      },
      { onSuccess: (hunt) => onDone(hunt.id) },
    );
  }

  return (
    <form className="card form" onSubmit={submit} aria-labelledby="nouvelle-chasse">
      <h2 id="nouvelle-chasse">Nouvelle chasse</h2>
      <label className="field">
        Observables : journaux, export pare-feu, liste d'un bulletin (une valeur par ligne ou séparées
        par des espaces)
        <textarea
          className="mono"
          rows={7}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={"185.220.101.1\nbeacon.cdn-update.duckdns.org\nhxxp://kq3zx9vw7plm2nbt[.]net/a"}
        />
      </label>
      <p className="muted" aria-live="polite">
        {batch.values.length > 0
          ? `${plural(batch.values.length, "observable")}`
          : assetOnly
            ? "Inventaire seul : la base d'IOC n'est pas lue."
            : "Aucun observable : la chasse portera sur toute la base d'IOC actifs."}
        {batch.duplicates > 0 ? ` · ${plural(batch.duplicates, "doublon")} retiré${batch.duplicates > 1 ? "s" : ""}` : ""}
        {batch.overflow > 0
          ? ` · ${formatNumber(batch.overflow)} au-delà de ${formatNumber(MAX_HUNT_OBSERVABLES)} non envoyés`
          : ""}
      </p>
      <label className="field">
        Inventaire d'actifs, pour la règle des CVE exploitables (séparés par des virgules)
        <input
          value={assetsText}
          onChange={(e) => setAssetsText(e.target.value)}
          placeholder="FortiOS, Exchange, Confluence"
          maxLength={8000}
        />
      </label>
      <fieldset className="rules">
        <legend>Règles</legend>
        {rules.map((rule) => (
          <label key={rule.id} className="check rule">
            <input type="checkbox" checked={selected.has(rule.id)} onChange={() => toggle(rule.id)} />
            <LevelBadge level={rule.severity} />
            <span>
              <strong>{rule.name}</strong> <span className="mono muted">{rule.id}</span>
              <br />
              <span className="muted">{rule.description}</span>
            </span>
          </label>
        ))}
      </fieldset>
      {wholeBase && (
        <label className="check">
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
          Je confirme la chasse sur toute la base (des centaines de milliers d'IOC : plusieurs
          minutes, comme la chasse planifiée du worker)
        </label>
      )}
      {assetOnly && assets.length === 0 && batch.values.length === 0 && (
        <p className="reason" style={{ textAlign: "left" }}>
          La règle des CVE exploitables a besoin d'un inventaire d'actifs.
        </p>
      )}
      {run.error && (
        <p className="notice error" role="alert">
          Chasse refusée : {run.error.message}
        </p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          Fermer
        </button>
        <button className="btn primary" type="submit" disabled={!ready || run.isPending}>
          {run.isPending ? "Chasse en cours…" : wholeBase ? "Chasser sur toute la base" : "Lancer la chasse"}
        </button>
      </div>
    </form>
  );
}

// --- Sessions -------------------------------------------------------------------------------

function HuntTable({
  hunts,
  selectedId,
  onSelect,
}: {
  hunts: Hunt[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const fresh = useFresh(hunts.map((h) => h.id));

  function onKey(event: KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(hunts[index].id);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = hunts[index + (event.key === "ArrowDown" ? 1 : -1)];
      if (next) {
        onSelect(next.id);
        document.getElementById(`chasse-${next.id}`)?.focus();
      }
    }
  }

  return (
    <table className="table selectable" aria-label="Sessions de chasse">
      <thead>
        <tr>
          <th>Lancée</th>
          <th>Origine</th>
          <th>État</th>
          <th className="num">Observables</th>
          <th className="num">Correspondances</th>
        </tr>
      </thead>
      <tbody>
        {hunts.map((hunt, index) => {
          const started = parseDate(hunt.started_at);
          return (
            <tr
              key={hunt.id}
              id={`chasse-${hunt.id}`}
              tabIndex={0}
              aria-current={hunt.id === selectedId ? "true" : undefined}
              className={fresh.has(hunt.id) ? "fresh" : undefined}
              onClick={() => onSelect(hunt.id)}
              onKeyDown={(event) => onKey(event, index)}
            >
              <td className="muted">{started ? `il y a ${formatAge(started)}` : "—"}</td>
              <td>{TRIGGER[hunt.trigger] ?? hunt.trigger}</td>
              <td>
                <StatusBadge status={hunt.status} />
              </td>
              <td className="num mono">{formatNumber(hunt.observables_count)}</td>
              <td className="num mono">
                {hunt.matches_count > 0 ? <strong>{formatNumber(hunt.matches_count)}</strong> : "0"}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// --- Résultats d'une session ----------------------------------------------------------------

function Matches({ huntId, rules }: { huntId: string; rules: HuntRule[] }) {
  const [filters, setFilters] = useState<MatchFilters>({});
  const [offset, setOffset] = useState(0);
  const query = useHuntMatches(huntId, filters, offset);
  const names = new Map(rules.map((r) => [r.id, r.name]));
  const byRule = query.data?.by_rule ?? {};

  const change = (next: MatchFilters) => {
    setFilters(next);
    setOffset(0);
  };

  return (
    <>
      <div className="row" style={{ marginBottom: 8 }}>
        <select
          className="compact"
          aria-label="Règle"
          value={filters.ruleId ?? ""}
          onChange={(e) => change({ ...filters, ruleId: e.target.value || undefined })}
        >
          <option value="">Toutes les règles</option>
          {rules.map((rule) => (
            <option key={rule.id} value={rule.id}>
              {rule.id} · {rule.name} ({formatNumber(byRule[rule.id] ?? 0)})
            </option>
          ))}
        </select>
        <select
          className="compact"
          aria-label="Sévérité"
          value={filters.severity ?? ""}
          onChange={(e) => change({ ...filters, severity: e.target.value || undefined })}
        >
          <option value="">Toutes sévérités</option>
          {SEVERITY_ORDER.map((level) => (
            <option key={level} value={level}>
              {levelLabel(level)}
            </option>
          ))}
        </select>
      </div>
      <QueryState query={query} empty={(page) => page.items.length === 0}>
        {(page) => (
          <>
            <ul className="list matches">
              {page.items.map((match, index) => (
                <li key={`${match.rule_id}-${match.observable}-${match.cve_id ?? ""}-${index}`}>
                  <LevelBadge level={match.severity} />
                  <div className="grow">
                    <div className="mono ellipsis" title={match.observable}>
                      {match.indicator_id ? (
                        <Link to={`/indicateurs?ioc=${match.indicator_id}`}>{match.observable}</Link>
                      ) : (
                        match.observable
                      )}
                    </div>
                    <div className="muted">
                      <span className="mono">{match.rule_id}</span> · {names.get(match.rule_id) ?? ""} —{" "}
                      {match.detail}
                      {match.cve_id && (
                        <>
                          {" "}
                          · <Link to={`/cve?cve=${encodeURIComponent(match.cve_id)}`}>{match.cve_id}</Link>
                        </>
                      )}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
            <Pager
              pageSize={MATCH_PAGE_SIZE}
              offset={offset}
              shown={page.items.length}
              total={page.total}
              busy={query.isPlaceholderData}
              onOffset={setOffset}
            />
          </>
        )}
      </QueryState>
    </>
  );
}

function HuntPanel({ hunt, rules }: { hunt: Hunt; rules: HuntRule[] }) {
  const { utc } = useTimeZone();
  const started = parseDate(hunt.started_at);
  const ruleIds = hunt.rules.split(",").filter(Boolean);
  const names = new Map(rules.map((r) => [r.id, r.name]));

  return (
    <aside className="card detail" aria-label="Résultats de la session">
      <section>
        <div className="title">
          <StatusBadge status={hunt.status} />
          <span>Chasse {(TRIGGER[hunt.trigger] ?? hunt.trigger).toLowerCase()}</span>
        </div>
        <p className="muted" style={{ margin: "4px 0 0" }}>
          {started ? `${formatDateTime(started, utc)} · ${durationOf(hunt)}` : "—"}
        </p>
      </section>

      <section>
        <h3>Périmètre</h3>
        <dl className="facts">
          <dt>Observables</dt>
          <dd>
            {formatNumber(hunt.observables_count)}
            {hunt.rejected_count > 0 ? ` (${formatNumber(hunt.rejected_count)} rejetés : format invalide)` : ""}
          </dd>
          <dt>Actifs</dt>
          <dd>{hunt.assets || "—"}</dd>
          <dt>Règles</dt>
          <dd>{ruleIds.map((id) => names.get(id) ?? id).join(", ")}</dd>
          <dt>Correspondances</dt>
          <dd className="mono">{formatNumber(hunt.matches_count)}</dd>
        </dl>
        {hunt.errors && (
          <p className="notice error" role="alert" style={{ whiteSpace: "pre-wrap", marginTop: 8 }}>
            {hunt.errors}
          </p>
        )}
      </section>

      <section>
        <h3>Correspondances</h3>
        {hunt.matches_count === 0 ? (
          <p className="muted">Aucune : rien de connu ni de suspect dans ce périmètre.</p>
        ) : (
          <Matches key={hunt.id} huntId={hunt.id} rules={rules} />
        )}
      </section>
    </aside>
  );
}

// --- Page -----------------------------------------------------------------------------------

export function Hunting() {
  const { user } = useAuth();
  const canAct = user ? RESPONDER_ROLES.has(user.role) : false;
  const { search, navigate } = useLocation();
  const requested = asUuid(new URLSearchParams(search).get("session"));
  const [creating, setCreating] = useState(false);

  const rules = useHuntRules();
  const hunts = useHunts();
  const list = hunts.data ?? [];
  const listed = list.find((h) => h.id === requested);
  // Session partagée par adresse mais hors des 50 dernières : son résumé est lu à part.
  const single = useHunt(requested, Boolean(requested) && hunts.isSuccess && !listed);
  const selected: Hunt | undefined = requested ? (listed ?? single.data) : list[0];

  const select = (id: string) => navigate(`/chasse?session=${encodeURIComponent(id)}`, { replace: true });

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Chasse</h1>
          <p>Confronter des observables, un inventaire ou toute la base aux règles de détection</p>
        </div>
        {canAct && !creating && (
          <button className="btn primary" type="button" onClick={() => setCreating(true)}>
            Nouvelle chasse
          </button>
        )}
      </div>

      {creating && rules.data && (
        <div style={{ marginBottom: 16 }}>
          <NewHunt
            rules={rules.data}
            onClose={() => setCreating(false)}
            onDone={(id) => {
              setCreating(false);
              select(id);
            }}
          />
        </div>
      )}

      <div className="split">
        <section className="card">
          <div className="toolbar">
            <span className="muted">
              {hunts.data ? `${plural(list.length, "session")}${list.length >= 50 ? " (50 dernières)" : ""}` : " "}
            </span>
          </div>
          <QueryState query={hunts} empty={(data) => data.length === 0}>
            {(data) => <HuntTable hunts={data} selectedId={selected?.id ?? null} onSelect={select} />}
          </QueryState>
        </section>

        {selected && rules.data ? (
          <HuntPanel key={selected.id} hunt={selected} rules={rules.data} />
        ) : (
          <aside className="card detail">
            <p className="empty">
              {hunts.isPending || single.isFetching
                ? "Chargement…"
                : single.isError
                  ? `Session introuvable : ${single.error.message}`
                  : "Aucune session. Lancez une chasse, ou attendez la chasse planifiée du worker."}
            </p>
          </aside>
        )}
      </div>
    </>
  );
}
