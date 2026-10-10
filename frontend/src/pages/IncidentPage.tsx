// Page d'un incident (investigation) : cycle de vie, chronologie immuable, transitions,
// notes, assignation, éléments associés. Une « action menée » est une déclaration de
// l'analyste : ILLWATCH l'enregistre, il ne l'exécute pas (et le dit).
import { useState, type FormEvent } from "react";

import {
  useAddNote,
  useAssign,
  useLinkCve,
  useLinkIndicator,
  useTransition,
} from "../api/mutations";
import { useIncident, useIndicator } from "../api/queries";
import type { IncidentDetail, IncidentEvent } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { LevelBadge } from "../components/Badge";
import { QueryState } from "../components/QueryState";
import { formatAge, formatDateTime, parseDate } from "../lib/format";
import { INCIDENT_STATUS } from "../lib/levels";
import { Link } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { RESPONDER_ROLES } from "./Incidents";

const LIFECYCLE = ["NOUVEAU", "ANALYSE", "CONFINEMENT", "ERADICATION", "RECUPERATION", "CLOTURE"];

const EVENT_LABEL: Record<string, string> = {
  CREATED: "Ouverture",
  STATUS_CHANGE: "Changement de statut",
  ASSIGNED: "Assignation",
  COMMENT: "Commentaire",
  IOC_ATTACHED: "IOC associé",
  CVE_ATTACHED: "CVE associée",
  ACTION_TAKEN: "Action déclarée par l'analyste",
};

function Lifecycle({ status }: { status: string }) {
  const current = LIFECYCLE.indexOf(status);
  return (
    <ol className="stepper" aria-label="Cycle de vie de l'incident">
      {LIFECYCLE.map((step, index) => (
        <li
          key={step}
          className={index < current ? "past" : index === current ? "current" : undefined}
          aria-current={index === current ? "step" : undefined}
        >
          {INCIDENT_STATUS[step]}
        </li>
      ))}
    </ol>
  );
}

function Author({ id }: { id: string | null }) {
  const { user } = useAuth();
  if (!id) return <span className="muted">système</span>;
  return <span className="muted">{id === user?.id ? "vous" : "un analyste"}</span>;
}

function Timeline({ events }: { events: IncidentEvent[] }) {
  const { utc } = useTimeZone();
  return (
    <ol className="timeline">
      {[...events].reverse().map((event) => {
        const at = parseDate(event.created_at);
        return (
          <li key={event.id}>
            <span className="mono muted">{at ? formatDateTime(at, utc) : "—"}</span>
            <div>
              <span className="kind">
                {EVENT_LABEL[event.event_type] ?? event.event_type} · <Author id={event.author_id} />
              </span>
              <span style={{ whiteSpace: "pre-wrap" }}>{event.message}</span>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function Transitions({ incident }: { incident: IncidentDetail }) {
  const transition = useTransition(incident.id);
  const [target, setTarget] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [summary, setSummary] = useState("");

  if (incident.next_states.length === 0) {
    return <p className="muted">Incident clôturé : seuls les commentaires restent possibles.</p>;
  }
  const forward = incident.next_states.filter((s) => s !== "ANALYSE" || incident.status === "NOUVEAU");
  const back = incident.next_states.includes("ANALYSE") && incident.status !== "NOUVEAU";

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!target) return;
    transition.mutate(
      {
        target,
        note: note.trim() || undefined,
        closure_summary: target === "CLOTURE" ? summary.trim() : undefined,
      },
      {
        onSuccess: () => {
          setTarget(null);
          setNote("");
          setSummary("");
        },
      },
    );
  }

  return (
    <form className="form" onSubmit={submit}>
      <div className="row">
        {forward.map((state) => (
          <button
            key={state}
            type="button"
            className={`btn${target === state ? " primary" : ""}`}
            aria-pressed={target === state}
            onClick={() => setTarget(state)}
          >
            Passer en {INCIDENT_STATUS[state]?.toLowerCase() ?? state}
          </button>
        ))}
        {back && (
          <button
            type="button"
            className={`btn quiet${target === "ANALYSE" ? " primary" : ""}`}
            aria-pressed={target === "ANALYSE"}
            onClick={() => setTarget("ANALYSE")}
          >
            Revenir en analyse
          </button>
        )}
      </div>
      {target && (
        <>
          {target === "CLOTURE" && (
            <label className="field">
              Résumé de clôture (obligatoire : cause, mesures, enseignements)
              <textarea required value={summary} onChange={(e) => setSummary(e.target.value)} />
            </label>
          )}
          <label className="field">
            Note jointe au changement (facultative)
            <input value={note} maxLength={5000} onChange={(e) => setNote(e.target.value)} />
          </label>
          {transition.error && (
            <p className="notice error" role="alert">
              {transition.error.message}
            </p>
          )}
          <div className="actions">
            <button className="btn quiet" type="button" onClick={() => setTarget(null)}>
              Annuler
            </button>
            <button className="btn primary" type="submit" disabled={transition.isPending}>
              {transition.isPending ? "Enregistrement…" : `Confirmer : ${INCIDENT_STATUS[target]}`}
            </button>
          </div>
        </>
      )}
    </form>
  );
}

function NoteForm({ incident }: { incident: IncidentDetail }) {
  const add = useAddNote(incident.id);
  const [message, setMessage] = useState("");
  const [kind, setKind] = useState<"COMMENT" | "ACTION_TAKEN">("COMMENT");
  const closed = incident.status === "CLOTURE";

  function submit(event: FormEvent) {
    event.preventDefault();
    add.mutate({ message: message.trim(), kind }, { onSuccess: () => setMessage("") });
  }

  return (
    <form className="form" onSubmit={submit}>
      <div className="seg" role="group" aria-label="Type de note">
        <button type="button" aria-pressed={kind === "COMMENT"} onClick={() => setKind("COMMENT")}>
          Commentaire
        </button>
        <button
          type="button"
          aria-pressed={kind === "ACTION_TAKEN"}
          disabled={closed}
          onClick={() => setKind("ACTION_TAKEN")}
        >
          Action menée
        </button>
      </div>
      <label className="field">
        {kind === "ACTION_TAKEN"
          ? "Action menée (déclarée par vous, enregistrée telle quelle : ILLWATCH ne l'exécute pas)"
          : "Commentaire"}
        <textarea required value={message} maxLength={20000} onChange={(e) => setMessage(e.target.value)} />
      </label>
      {add.error && (
        <p className="notice error" role="alert">
          {add.error.message}
        </p>
      )}
      <div className="actions">
        <button className="btn primary" type="submit" disabled={add.isPending || !message.trim()}>
          {add.isPending ? "Ajout…" : "Ajouter à la chronologie"}
        </button>
      </div>
    </form>
  );
}

function IndicatorItem({ id }: { id: string }) {
  const query = useIndicator(id);
  if (!query.data) return <li className="mono muted">{query.isError ? "IOC illisible" : "…"}</li>;
  return (
    <li>
      <LevelBadge level={query.data.severity} />
      <Link to={`/indicateurs?ioc=${id}`} className="mono ellipsis" title={query.data.value}>
        {query.data.type} {query.data.value}
      </Link>
    </li>
  );
}

function Links({ incident, canAct }: { incident: IncidentDetail; canAct: boolean }) {
  const linkCve = useLinkCve(incident.id);
  const linkIoc = useLinkIndicator(incident.id);
  const [cve, setCve] = useState("");
  const [ioc, setIoc] = useState("");
  const error = linkCve.error ?? linkIoc.error;

  return (
    <>
      <h3>CVE ({incident.cve_ids.length})</h3>
      {incident.cve_ids.length === 0 ? (
        <p className="muted">Aucune.</p>
      ) : (
        <ul className="list">
          {incident.cve_ids.map((id) => (
            <li key={id} className="mono">
              <Link to={`/cve?cve=${encodeURIComponent(id)}`}>{id}</Link>
            </li>
          ))}
        </ul>
      )}
      <h3 style={{ marginTop: 16 }}>Indicateurs ({incident.indicator_ids.length})</h3>
      {incident.indicator_ids.length === 0 ? (
        <p className="muted">Aucun.</p>
      ) : (
        <ul className="list">
          {incident.indicator_ids.slice(0, 20).map((id) => (
            <IndicatorItem key={id} id={id} />
          ))}
        </ul>
      )}
      {incident.indicator_ids.length > 20 && (
        <p className="muted">… et {incident.indicator_ids.length - 20} autres.</p>
      )}
      {canAct && (
        <div className="form" style={{ marginTop: 16 }}>
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault();
              linkCve.mutate(cve.trim().toUpperCase(), { onSuccess: () => setCve("") });
            }}
          >
            <label className="field" style={{ flex: 1 }}>
              Associer une CVE
              <input
                className="mono"
                placeholder="CVE-2026-12345"
                pattern="[Cc][Vv][Ee]-\d{4}-\d{4,}"
                value={cve}
                onChange={(e) => setCve(e.target.value)}
              />
            </label>
            <button className="btn" type="submit" disabled={!cve.trim() || linkCve.isPending}>
              Associer
            </button>
          </form>
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault();
              linkIoc.mutate(ioc.trim(), { onSuccess: () => setIoc("") });
            }}
          >
            <label className="field" style={{ flex: 1 }}>
              Associer un IOC déjà connu (IP, domaine, URL, empreinte)
              <input className="mono" value={ioc} maxLength={2048} onChange={(e) => setIoc(e.target.value)} />
            </label>
            <button className="btn" type="submit" disabled={!ioc.trim() || linkIoc.isPending}>
              Associer
            </button>
          </form>
          {error && (
            <p className="notice error" role="alert">
              {error.message}
            </p>
          )}
        </div>
      )}
    </>
  );
}

function Assignment({ incident, canAct }: { incident: IncidentDetail; canAct: boolean }) {
  const { user } = useAuth();
  const assign = useAssign(incident.id);
  const mine = incident.assigned_to !== null && incident.assigned_to === user?.id;
  return (
    <div className="row">
      <span>
        {incident.assigned_to ? (mine ? "Assigné à vous" : "Assigné à un analyste") : "Non assigné"}
      </span>
      {canAct && !mine && user && (
        <button className="btn" type="button" disabled={assign.isPending} onClick={() => assign.mutate(user.id)}>
          M'assigner
        </button>
      )}
      {canAct && incident.assigned_to && (
        <button className="btn quiet" type="button" disabled={assign.isPending} onClick={() => assign.mutate(null)}>
          Retirer l'assignation
        </button>
      )}
      {assign.error && <span className="notice error">{assign.error.message}</span>}
    </div>
  );
}

export function IncidentPage({ incidentId }: { incidentId: string }) {
  const query = useIncident(incidentId);
  const { user } = useAuth();
  const { utc } = useTimeZone();
  const canAct = user ? RESPONDER_ROLES.has(user.role) : false;

  return (
    <>
      <p style={{ margin: "0 0 12px" }}>
        <Link to="/incidents">← Tous les incidents</Link>
      </p>
      <QueryState query={query}>
        {(incident) => {
          const opened = parseDate(incident.created_at);
          const closed = parseDate(incident.closed_at);
          return (
            <>
              <div className="page-head">
                <div>
                  <h1 style={{ display: "flex", gap: 12, alignItems: "center" }}>
                    <LevelBadge level={incident.severity} />
                    {incident.title}
                  </h1>
                  <p>
                    {INCIDENT_STATUS[incident.status]} · ouvert {opened ? `il y a ${formatAge(opened)}` : "—"}
                    {opened ? ` (${formatDateTime(opened, utc)})` : ""}
                    {closed ? ` · clôturé ${formatDateTime(closed, utc)}` : ""}
                    {incident.source_alert_id ? " · issu d'une alerte CVE" : ""}
                  </p>
                </div>
              </div>

              <section className="card" style={{ marginBottom: 16 }}>
                <Lifecycle status={incident.status} />
              </section>

              <div className="page-grid">
                <div className="grid">
                  <section className="card">
                    <h2>Description</h2>
                    <p style={{ whiteSpace: "pre-wrap" }}>{incident.description}</p>
                    {incident.closure_summary && (
                      <>
                        <h2>Résumé de clôture</h2>
                        <p style={{ whiteSpace: "pre-wrap" }}>{incident.closure_summary}</p>
                      </>
                    )}
                  </section>
                  <section className="card">
                    <h2>Chronologie</h2>
                    <p className="muted" style={{ marginTop: 0 }}>
                      Immuable : chaque étape est conservée, rien n'est modifié ni effacé.
                    </p>
                    <Timeline events={incident.timeline} />
                  </section>
                </div>

                <aside className="grid">
                  <section className="card detail">
                    <section>
                      <h3>Statut</h3>
                      {canAct ? (
                        <Transitions incident={incident} />
                      ) : (
                        <p className="reason" style={{ textAlign: "left" }}>
                          Changements de statut réservés aux rôles analyste et administrateur.
                        </p>
                      )}
                    </section>
                    <section>
                      <h3>Assignation</h3>
                      <Assignment incident={incident} canAct={canAct} />
                    </section>
                    {canAct && (
                      <section>
                        <h3>Ajouter à la chronologie</h3>
                        <NoteForm incident={incident} />
                      </section>
                    )}
                  </section>
                  <section className="card detail">
                    <section>
                      <Links incident={incident} canAct={canAct} />
                    </section>
                  </section>
                </aside>
              </div>
            </>
          );
        }}
      </QueryState>
    </>
  );
}
