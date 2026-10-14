// Corrélations (M8, ADR-020) : ce que le renseignement dit de VOS actifs. File des évènements
// corrélés triée par gravité, panneau de détail qui explique chaque point du score, actions
// (acquitter, ouvrir l'incident). L'évènement choisi est dans l'adresse (?evenement=…).
import { useEffect, useState, type KeyboardEvent } from "react";

import {
  useAcknowledgeCorrelation,
  useFalsePositiveCorrelation,
  useIncidentFromCorrelation,
  useRunCorrelation,
} from "../api/mutations";
import { useCorrelations } from "../api/queries";
import type { Correlation } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { AttackSection } from "../components/Attack";
import { LevelBadge } from "../components/Badge";
import { QueryState } from "../components/QueryState";
import { formatAgo, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { countryName } from "../lib/iocs";
import { levelLabel, rankOf } from "../lib/levels";
import { asUuid, Link, useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { useFresh } from "../lib/useFresh";

type Scope = "open" | "all";

const RESPONDER_ROLES = new Set(["ADMIN", "ANALYST"]);

/** État lisible : un évènement clos par le moteur n'a pas été acquitté par un analyste. */
function stateLabel(acknowledgedAt: string | null | undefined, resolvedAt: string | null, utc: boolean): string {
  if (resolvedAt) {
    const when = parseDate(resolvedAt);
    return `clos automatiquement${when ? ` le ${formatDateTime(when, utc)}` : ""} : ne correspond plus (version hors plage, autre produit, IOC expiré…)`;
  }
  return acknowledgedAt ? "acquitté" : "à traiter";
}

export const RULE_LABEL: Record<string, string> = {
  "CORR-01": "CVE exploitée (KEV)",
  "CORR-02": "Exploit public",
  "CORR-03": "Actif dans un IOC",
};

const CRITICALITY: Record<string, string> = {
  CRITICAL: "critique",
  HIGH: "élevée",
  MEDIUM: "moyenne",
  LOW: "faible",
};

function text(detail: Correlation["detail"], key: string): string | null {
  const value = detail[key];
  return typeof value === "string" && value ? value : null;
}

function num(detail: Correlation["detail"], key: string): number | null {
  const value = detail[key];
  return typeof value === "number" ? value : null;
}

function points(value: number): string {
  return `+${value.toFixed(1).replace(".", ",")}`;
}

function byGravity(a: Correlation, b: Correlation): number {
  return rankOf(a.priority) - rankOf(b.priority) || b.score - a.score || b.last_seen.localeCompare(a.last_seen);
}

// --- File -------------------------------------------------------------------------------------

function EventTable({
  events,
  selectedId,
  onSelect,
}: {
  events: Correlation[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const fresh = useFresh(events.map((e) => e.id));
  const sorted = [...events].sort(byGravity);

  function onKey(event: KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(sorted[index].id);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = sorted[index + (event.key === "ArrowDown" ? 1 : -1)];
      if (next) {
        onSelect(next.id);
        document.getElementById(`correlation-${next.id}`)?.focus();
      }
    }
  }

  return (
    <table className="table selectable" aria-label="Évènements corrélés">
      <thead>
        <tr>
          <th>Priorité</th>
          <th>Règle</th>
          <th>Actif</th>
          <th>Cible</th>
          <th className="num">Score</th>
          <th>Vu</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((event, index) => {
          const seen = parseDate(event.last_seen);
          const target = event.cve_id ?? text(event.detail, "value") ?? "—";
          const classes = [fresh.has(event.id) ? "fresh" : "", event.acknowledged_at ? "done" : ""]
            .filter(Boolean)
            .join(" ");
          return (
            <tr
              key={event.id}
              id={`correlation-${event.id}`}
              tabIndex={0}
              aria-current={event.id === selectedId ? "true" : undefined}
              className={classes || undefined}
              onClick={() => onSelect(event.id)}
              onKeyDown={(e) => onKey(e, index)}
            >
              <td>
                <LevelBadge level={event.priority} />
              </td>
              <td className="muted">{RULE_LABEL[event.rule_id] ?? event.rule_id}</td>
              <td className="cell-title">{event.asset_name}</td>
              <td className="mono ellipsis cell-target" title={target}>
                {target}
              </td>
              <td className="num mono">{event.score.toFixed(1).replace(".", ",")}</td>
              <td className="muted">{seen ? formatAgo(seen) : "—"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// --- Détail -----------------------------------------------------------------------------------

function EventDetail({ event, onPinned }: { event: Correlation; onPinned: (id: string) => void }) {
  const { utc } = useTimeZone();
  const { user } = useAuth();
  const { navigate } = useLocation();
  const ack = useAcknowledgeCorrelation();
  const toIncident = useIncidentFromCorrelation();
  const falsePositive = useFalsePositiveCorrelation();
  const [openedId, setOpenedId] = useState<string | null>(null);
  const [qualifying, setQualifying] = useState(false);
  const [reason, setReason] = useState("");

  useEffect(() => {
    setOpenedId(null);
    setQualifying(false);
    setReason("");
    ack.reset();
    toIncident.reset();
    falsePositive.reset();
  }, [event.id]);

  const canAct = user ? RESPONDER_ROLES.has(user.role) : false;
  const detail = event.detail;
  const first = parseDate(event.first_seen);
  const last = parseDate(event.last_seen);
  const breakdown = (detail.breakdown ?? {}) as Record<string, number>;
  const signals = Array.isArray(detail.signals) ? (detail.signals as string[]) : [];
  const incidentId = openedId ?? event.incident_id;
  const error = ack.error ?? toIncident.error ?? falsePositive.error;
  const qualified = detail.false_positive as { reason?: string } | undefined;
  const value = text(detail, "value");
  const criticality = text(detail, "asset_criticality");

  return (
    <aside className="card detail" aria-label={`Détail : ${event.title}`}>
      {/* 1. Identité et priorité */}
      <section>
        <div className="title">
          <LevelBadge level={event.priority} />
          <span>{RULE_LABEL[event.rule_id] ?? event.rule_id}</span>
        </div>
        <p className="muted small">{event.title}</p>
      </section>

      {/* 2. Pourquoi : l'actif et ce qui le relie au renseignement */}
      <section>
        <h3>Pourquoi</h3>
        <dl className="facts">
          <dt>Actif</dt>
          <dd>
            <Link to={`/inventaire?actif=${encodeURIComponent(event.asset_id)}`}>{event.asset_name}</Link>
            {criticality ? ` · criticité ${CRITICALITY[criticality] ?? criticality}` : ""}
          </dd>
          {event.cve_id && (
            <>
              <dt>CVE</dt>
              <dd>
                <Link className="mono" to={`/cve?cve=${encodeURIComponent(event.cve_id)}`}>
                  {event.cve_id}
                </Link>
                {text(detail, "cve_priority") ? ` · ${levelLabel(text(detail, "cve_priority") ?? "")}` : ""}
              </dd>
              <dt>Produit reconnu</dt>
              <dd>{text(detail, "product") ?? "—"}</dd>
              <dt>Version</dt>
              <dd>
                {text(detail, "version") ?? "non déclarée"}
                {text(detail, "platform") ? ` sur ${text(detail, "platform")}` : ""}
                {text(detail, "version_label") ? (
                  <span className="cell-sub"> · {text(detail, "version_label")}</span>
                ) : null}
                {text(detail, "version_platforms") ? (
                  <span className="cell-sub"> · plateformes : {text(detail, "version_platforms")}</span>
                ) : null}
              </dd>
              <dt>Signaux</dt>
              <dd>{signals.length ? signals.join(", ") : "—"}</dd>
              {text(detail, "kev_due_date") && (
                <>
                  <dt>Échéance CISA</dt>
                  <dd>{text(detail, "kev_due_date")}</dd>
                </>
              )}
            </>
          )}
          {value && (
            <>
              <dt>Indicateur</dt>
              <dd>
                {event.indicator_id ? (
                  <Link className="mono" to={`/indicateurs?ioc=${encodeURIComponent(event.indicator_id)}`}>
                    {value}
                  </Link>
                ) : (
                  <span className="mono">{value}</span>
                )}
              </dd>
              <dt>Confiance</dt>
              <dd>
                {num(detail, "confidence") ?? "—"} / 100 · {num(detail, "sources") ?? 0} source(s)
              </dd>
              {(text(detail, "country") || num(detail, "asn")) && (
                <>
                  <dt>Localisation</dt>
                  <dd>
                    {countryName(text(detail, "country"))}
                    {num(detail, "asn") ? ` · AS${num(detail, "asn")} ${text(detail, "as_org") ?? ""}` : ""}
                  </dd>
                </>
              )}
              {text(detail, "description") && (
                <>
                  <dt>Contexte</dt>
                  <dd>{text(detail, "description")}</dd>
                </>
              )}
            </>
          )}
        </dl>
      </section>

      {/* 3. Score : chaque point justifié */}
      <section>
        <h3>Score</h3>
        <dl className="facts">
          <dt>Base de la règle</dt>
          <dd className="mono">{points(breakdown.base ?? 0)}</dd>
          <dt>Criticité de l'actif</dt>
          <dd className="mono">{points(breakdown.criticality ?? 0)}</dd>
          <dt>{event.cve_id ? "Risque de la CVE" : "Confiance de l'IOC"}</dt>
          <dd className="mono">{points(breakdown.signal ?? 0)}</dd>
          <dt>Total</dt>
          <dd className="mono">
            <strong>{event.score.toFixed(1).replace(".", ",")}</strong> / 100 · {levelLabel(event.priority)}
          </dd>
        </dl>
      </section>

      {/* 4. Historique */}
      <section>
        <h3>Historique</h3>
        <dl className="facts">
          <dt>Première détection</dt>
          <dd>{first ? formatDateTime(first, utc) : "—"}</dd>
          <dt>Dernière confirmation</dt>
          <dd>{last ? `${formatDateTime(last, utc)} · ${formatAgo(last)}` : "—"}</dd>
          <dt>État</dt>
          <dd>
            {qualified
              ? `faux positif (jamais rouvert) : ${qualified.reason ?? ""}`
              : stateLabel(event.acknowledged_at, text(detail, "resolved_at"), utc)}
          </dd>
        </dl>
      </section>

      <AttackSection context={event.attack} />

      {/* 5. Actions */}
      <section>
        {incidentId && (
          <p className="notice ok" role="status">
            Incident de réponse : <Link to={`/incidents/${incidentId}`}>ouvrir l'investigation</Link>
          </p>
        )}
        {error && (
          <p className="notice error" role="alert">
            Action refusée : {error.message}
          </p>
        )}
        <div className="actions">
          <button
            className="btn"
            type="button"
            disabled={!canAct || Boolean(event.acknowledged_at) || ack.isPending}
            onClick={() => ack.mutate(event.id, { onSuccess: () => onPinned(event.id) })}
          >
            {ack.isPending ? "Acquittement…" : "Acquitter"}
          </button>
          {incidentId ? (
            <button className="btn primary" type="button" onClick={() => navigate(`/incidents/${incidentId}`)}>
              Aller à l'incident
            </button>
          ) : (
            <button
              className="btn primary"
              type="button"
              disabled={!canAct || toIncident.isPending}
              onClick={() =>
                toIncident.mutate(event.id, {
                  onSuccess: (r) => {
                    setOpenedId(r.incident_id);
                    onPinned(event.id);
                  },
                })
              }
            >
              {toIncident.isPending ? "Ouverture…" : "Ouvrir l'incident"}
            </button>
          )}
        </div>
        {canAct && !qualified && !qualifying && (
          <div className="actions">
            <button className="btn quiet" type="button" onClick={() => setQualifying(true)}>
              Faux positif
            </button>
          </div>
        )}
        {qualifying && (
          <form
            className="form"
            onSubmit={(e) => {
              e.preventDefault();
              falsePositive.mutate(
                { eventId: event.id, reason: reason.trim() },
                {
                  onSuccess: () => {
                    setQualifying(false);
                    onPinned(event.id);
                  },
                },
              );
            }}
          >
            <label className="field">
              Pourquoi est-ce un faux positif ?{" "}
              {event.indicator_id ? "(l'IOC en cause passe aussi en liste d'exclusion)" : "(l'évènement ne sera plus rouvert)"}
              <input required minLength={5} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />
            </label>
            <div className="actions">
              <button className="btn quiet" type="button" onClick={() => setQualifying(false)}>
                Annuler
              </button>
              <button
                className="btn primary"
                type="submit"
                disabled={falsePositive.isPending || reason.trim().length < 5}
              >
                {falsePositive.isPending ? "Enregistrement…" : "Qualifier de faux positif"}
              </button>
            </div>
          </form>
        )}
        {!canAct && <p className="reason">Actions réservées aux rôles analyste et administrateur.</p>}
      </section>
    </aside>
  );
}

// --- Page -------------------------------------------------------------------------------------

export function Correlations() {
  const { search, navigate } = useLocation();
  const { user } = useAuth();
  const [scope, setScope] = useState<Scope>("open");
  const params = new URLSearchParams(search);
  const assetId = asUuid(params.get("actif"));
  const query = useCorrelations(scope, assetId);
  const run = useRunCorrelation();
  const requested = asUuid(params.get("evenement"));
  const events = query.data?.items ?? [];
  const found = events.find((e) => e.id === requested) ?? (requested ? undefined : [...events].sort(byGravity)[0]);
  // Acquitté ou passé en incident, l'évènement quitte la file « À traiter » : son panneau reste
  // affiché (avec le lien vers l'incident) tant que l'analyste n'en choisit pas un autre.
  const [kept, setKept] = useState<Correlation | null>(null);
  useEffect(() => {
    if (found) setKept(found);
  }, [found]);
  const selected = found ?? (kept && kept.id === requested ? kept : undefined);
  const canRun = user ? RESPONDER_ROLES.has(user.role) : false;
  const assetName = assetId ? (events[0]?.asset_name ?? "cet actif") : null;

  const select = (id: string) => {
    const filter = assetId ? `&actif=${encodeURIComponent(assetId)}` : "";
    navigate(`/correlations?evenement=${encodeURIComponent(id)}${filter}`, { replace: true });
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Corrélations</h1>
          <p>Ce que le renseignement dit de vos actifs : CVE exploitées, exploits publics, adresses listées</p>
        </div>
        <button className="btn" type="button" disabled={!canRun || run.isPending} onClick={() => run.mutate(undefined)}>
          {run.isPending ? "Corrélation…" : "Corréler maintenant"}
        </button>
      </div>
      {run.data && (
        <p className="notice ok gap-bottom" role="status">
          Passe terminée : {run.data.assets} actif(s), {run.data.created} nouvel(s) évènement(s),{" "}
          {run.data.updated} confirmé(s).
        </p>
      )}
      {run.error && (
        <p className="notice error gap-bottom" role="alert">
          Corrélation impossible : {run.error.message}
        </p>
      )}

      <div className="split">
        <section className="card">
          <div className="toolbar">
            <span className="muted">
              {query.data
                ? `${formatNumber(query.data.total)} évènement${query.data.total > 1 ? "s" : ""}${scope === "open" ? " à traiter" : ""}${query.data.total > events.length ? ` · ${events.length} plus graves affichés` : ""}`
                : " "}
              {assetName && (
                <>
                  {" "}
                  · {assetName} · <Link to="/correlations">tous les actifs</Link>
                </>
              )}
            </span>
            <div className="seg" role="group" aria-label="Évènements affichés">
              <button type="button" aria-pressed={scope === "open"} onClick={() => setScope("open")}>
                À traiter
              </button>
              <button type="button" aria-pressed={scope === "all"} onClick={() => setScope("all")}>
                Tous
              </button>
            </div>
          </div>
          <QueryState query={query}>
            {(page) =>
              page.items.length === 0 ? (
                <p className="empty">
                  Aucun évènement {scope === "open" ? "à traiter" : "corrélé"}. Déclarez vos produits, adresses et
                  domaines dans <Link to="/inventaire">l'inventaire</Link> : la corrélation tourne chaque heure.
                </p>
              ) : (
                <EventTable events={events} selectedId={selected?.id ?? null} onSelect={select} />
              )
            }
          </QueryState>
        </section>

        {selected ? (
          <EventDetail event={selected} onPinned={select} />
        ) : (
          <aside className="card detail">
            <p className="empty">
              {query.isPending
                ? "Chargement…"
                : requested
                  ? "Cet évènement n'est pas dans la liste affichée (déjà traité ?). Essayez « Tous »."
                  : "Rien à traiter pour le moment."}
            </p>
          </aside>
        )}
      </div>
    </>
  );
}
