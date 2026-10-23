// Page d'un incident (investigation) : cycle de vie, chronologie immuable, transitions,
// notes, assignation, éléments associés. Une « action menée » est une déclaration de
// l'analyste : ILL Watch l'enregistre, il ne l'exécute pas (et le dit).
import { ArrowLeft } from "lucide-react";
import { useState, type FormEvent } from "react";

import {
  useAddNote,
  useAssign,
  useCreateExclusion,
  useEscalate,
  useHuntFromIncident,
  useLinkCve,
  useLinkIndicator,
  useTransition,
} from "../api/mutations";
import { useIncident, useIndicator } from "../api/queries";
import type { IncidentDetail, IncidentEvent } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { AttackSection } from "../components/Attack";
import { LevelBadge } from "../components/Badge";
import { QueryState } from "../components/QueryState";
import { currentLang } from "../i18n/core";
import { formatAgo, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { splitBatch } from "../lib/iocs";
import { INCIDENT_STATUS, PHASE_LABEL, TIER_LABEL } from "../lib/levels";
import { Link } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { t } from "./IncidentPage.i18n";
import { RESPONDER_ROLES } from "./Incidents";

const LIFECYCLE = ["NOUVEAU", "ANALYSE", "CONFINEMENT", "ERADICATION", "RECUPERATION", "CLOTURE"];

type Key = Parameters<typeof t>[0];
const EVENTS = new Set([
  "CREATED",
  "STATUS_CHANGE",
  "ASSIGNED",
  "COMMENT",
  "IOC_ATTACHED",
  "CVE_ATTACHED",
  "ACTION_TAKEN",
  "ESCALATED",
  "HUNT_RUN",
  "IOC_EXCLUDED",
]);
const HUNT_STATUSES = new Set(["EN_COURS", "TERMINEE", "PARTIELLE", "ECHEC"]);
const eventLabel = (type: string) => (EVENTS.has(type) ? t(`event.${type}` as Key) : type);
const huntStatus = (status: string) => (HUNT_STATUSES.has(status) ? t(`hunt.${status}` as Key) : status);

/** Statut dans une phrase : minuscule en français et en espagnol (« Passer en confinement »). */
function inSentence(label: string): string {
  return currentLang() === "fr" || currentLang() === "es" ? label.toLowerCase() : label;
}

function Lifecycle({ status }: { status: string }) {
  const current = LIFECYCLE.indexOf(status);
  return (
    <ol className="stepper" aria-label={t("lifecycle")}>
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
  if (!id) return <span className="muted">{t("system")}</span>;
  return <span className="muted">{id === user?.id ? t("you") : t("anAnalyst")}</span>;
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
                {eventLabel(event.event_type)} · <Author id={event.author_id} />
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
    return <p className="muted">{t("closedOnlyComments")}</p>;
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
            {t("moveTo", { status: INCIDENT_STATUS[state] ? inSentence(INCIDENT_STATUS[state]) : state })}
          </button>
        ))}
        {back && (
          <button
            type="button"
            className={`btn quiet${target === "ANALYSE" ? " primary" : ""}`}
            aria-pressed={target === "ANALYSE"}
            onClick={() => setTarget("ANALYSE")}
          >
            {t("backToAnalysis")}
          </button>
        )}
      </div>
      {target && (
        <>
          {target === "CLOTURE" && (
            <label className="field">
              {t("closureSummary")}
              <textarea required value={summary} onChange={(e) => setSummary(e.target.value)} />
            </label>
          )}
          <label className="field">
            {t("changeNote")}
            <input value={note} maxLength={5000} onChange={(e) => setNote(e.target.value)} />
          </label>
          {transition.error && (
            <p className="notice error" role="alert">
              {transition.error.message}
            </p>
          )}
          <div className="actions">
            <button className="btn quiet" type="button" onClick={() => setTarget(null)}>
              {t("cancel")}
            </button>
            <button className="btn primary" type="submit" disabled={transition.isPending}>
              {transition.isPending ? t("saving") : t("confirm", { status: INCIDENT_STATUS[target] ?? target })}
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
      <div className="seg" role="group" aria-label={t("noteType")}>
        <button type="button" aria-pressed={kind === "COMMENT"} onClick={() => setKind("COMMENT")}>
          {t("comment")}
        </button>
        <button
          type="button"
          aria-pressed={kind === "ACTION_TAKEN"}
          disabled={closed}
          onClick={() => setKind("ACTION_TAKEN")}
        >
          {t("actionTaken")}
        </button>
      </div>
      <label className="field">
        {kind === "ACTION_TAKEN"
          ? t("actionTakenField")
          : t("comment")}
        <textarea required value={message} maxLength={20000} onChange={(e) => setMessage(e.target.value)} />
      </label>
      {add.error && (
        <p className="notice error" role="alert">
          {add.error.message}
        </p>
      )}
      <div className="actions">
        <button className="btn primary" type="submit" disabled={add.isPending || !message.trim()}>
          {add.isPending ? t("adding") : t("addToTimeline")}
        </button>
      </div>
    </form>
  );
}

function IndicatorItem({ id, incidentId, canAct }: { id: string; incidentId: string; canAct: boolean }) {
  const query = useIndicator(id);
  const exclude = useCreateExclusion();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  if (!query.data) return <li className="mono muted">{query.isError ? t("iocUnreadable") : "…"}</li>;
  const ioc = query.data;
  return (
    <li className="ioc-item">
      <div className="row tight">
        <LevelBadge level={ioc.severity} />
        <Link to={`/indicateurs?ioc=${id}`} className="mono ellipsis grow" title={ioc.value}>
          {ioc.type} {ioc.value}
        </Link>
        {ioc.exclusion ? (
          <span className="badge tag" title={ioc.exclusion.reason}>
            {t("falsePositiveTag")}
          </span>
        ) : (
          canAct &&
          !open && (
            <button className="btn quiet small" type="button" onClick={() => setOpen(true)}>
              {t("falsePositive")}
            </button>
          )
        )}
      </div>
      {open && !ioc.exclusion && (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            exclude.mutate(
              { value: ioc.value, reason: reason.trim(), incident_id: incidentId },
              { onSuccess: () => setOpen(false) },
            );
          }}
        >
          <label className="field">
            {t("whySafe")}
            <input required minLength={5} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          {exclude.error && (
            <p className="notice error" role="alert">
              {exclude.error.message}
            </p>
          )}
          <div className="actions">
            <button className="btn quiet" type="button" onClick={() => setOpen(false)}>
              {t("cancel")}
            </button>
            <button className="btn primary" type="submit" disabled={exclude.isPending || reason.trim().length < 5}>
              {exclude.isPending ? t("excluding") : t("exclude")}
            </button>
          </div>
        </form>
      )}
    </li>
  );
}

function Escalation({ incident, canAct }: { incident: IncidentDetail; canAct: boolean }) {
  const escalate = useEscalate(incident.id);
  const [reason, setReason] = useState("");
  const next = incident.tier === "L1" ? "L2" : incident.tier === "L2" ? "L3" : null;
  const closed = incident.status === "CLOTURE";
  return (
    <>
      <p style={{ margin: 0 }}>
        <span className="badge tier">{incident.tier}</span> {TIER_LABEL[incident.tier]?.split(" · ")[1] ?? ""}
      </p>
      {canAct && next && !closed && (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            escalate.mutate({ reason: reason.trim() }, { onSuccess: () => setReason("") });
          }}
        >
          <label className="field">
            {t("escalationReason", { tier: TIER_LABEL[next] ?? next })}
            <input
              required
              minLength={5}
              maxLength={2000}
              placeholder={next === "L2" ? t("escalationHintL2") : t("escalationHintL3")}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
          {escalate.error && (
            <p className="notice error" role="alert">
              {escalate.error.message}
            </p>
          )}
          <div className="actions">
            <button className="btn" type="submit" disabled={escalate.isPending || reason.trim().length < 5}>
              {escalate.isPending ? t("escalating") : t("escalateTo", { tier: next })}
            </button>
          </div>
        </form>
      )}
      {!next && <p className="muted small">{t("highestTier")}</p>}
    </>
  );
}

function IncidentHunting({ incident, canAct }: { incident: IncidentDetail; canAct: boolean }) {
  const hunt = useHuntFromIncident(incident.id);
  const { utc } = useTimeZone();
  const [extra, setExtra] = useState("");
  const closed = incident.status === "CLOTURE";
  const observables = splitBatch(extra, 1000).values;
  return (
    <>
      {canAct && !closed && (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            hunt.mutate(observables, { onSuccess: () => setExtra("") });
          }}
        >
          <p className="muted small" style={{ margin: 0 }}>
            {t("huntScope", { count: incident.indicator_ids.length })}
          </p>
          <label className="field">
            {t("extraObservables")}
            <textarea className="mono" rows={3} value={extra} onChange={(e) => setExtra(e.target.value)} />
          </label>
          {hunt.error && (
            <p className="notice error" role="alert">
              {hunt.error.message}
            </p>
          )}
          {hunt.data && (
            <p className="notice ok" role="status">
              {t("huntResult", { matches: hunt.data.matches_count, observables: hunt.data.observables_count })}
            </p>
          )}
          <div className="actions">
            <button className="btn" type="submit" disabled={hunt.isPending}>
              {hunt.isPending ? t("hunting") : t("huntFromIncident")}
            </button>
          </div>
        </form>
      )}
      {incident.hunts.length > 0 && (
        <ul className="list">
          {incident.hunts.map((h) => {
            const at = parseDate(h.started_at);
            return (
              <li key={h.id}>
                <Link to={`/chasse?session=${encodeURIComponent(h.id)}`}>
                  {at ? formatDateTime(at, utc) : "—"}
                </Link>{" "}
                <span className="muted">
                  {t("huntLine", { matches: formatNumber(h.matches_count), status: huntStatus(h.status) })}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </>
  );
}

function Recommendations({ incident }: { incident: IncidentDetail }) {
  if (incident.recommendations.length === 0) return null;
  return (
    <section className="card">
      <h2>{t("recommendations")}</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        {t("recommendationsIntro")}
      </p>
      <ol className="recommendations">
        {incident.recommendations.map((r, index) => (
          <li key={`${r.phase}-${index}`} className={r.current ? "current" : undefined}>
            <span className="badge tag">{PHASE_LABEL[r.phase] ?? r.phase}</span>
            <div>
              <strong>{r.title}</strong>
              {r.current && <span className="muted small">{t("currentPhase")}</span>}
              <p>{r.detail}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
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
      <h3>{t("cveCount", { count: incident.cve_ids.length })}</h3>
      {incident.cve_ids.length === 0 ? (
        <p className="muted">{t("noneF")}</p>
      ) : (
        <ul className="list">
          {incident.cve_ids.map((id) => (
            <li key={id} className="mono">
              <Link to={`/cve?cve=${encodeURIComponent(id)}`}>{id}</Link>
            </li>
          ))}
        </ul>
      )}
      <h3 style={{ marginTop: 16 }}>{t("iocCount", { count: incident.indicator_ids.length })}</h3>
      {incident.indicator_ids.length === 0 ? (
        <p className="muted">{t("noneM")}</p>
      ) : (
        <ul className="list">
          {incident.indicator_ids.slice(0, 20).map((id) => (
            <IndicatorItem key={id} id={id} incidentId={incident.id} canAct={canAct} />
          ))}
        </ul>
      )}
      {incident.indicator_ids.length > 20 && (
        <p className="muted">{t("andOthers", { count: incident.indicator_ids.length - 20 })}</p>
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
              {t("linkCve")}
              <input
                className="mono"
                placeholder="CVE-2026-12345"
                pattern="[Cc][Vv][Ee]-\d{4}-\d{4,}"
                value={cve}
                onChange={(e) => setCve(e.target.value)}
              />
            </label>
            <button className="btn" type="submit" disabled={!cve.trim() || linkCve.isPending}>
              {t("link")}
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
              {t("linkIoc")}
              <input className="mono" value={ioc} maxLength={2048} onChange={(e) => setIoc(e.target.value)} />
            </label>
            <button className="btn" type="submit" disabled={!ioc.trim() || linkIoc.isPending}>
              {t("link")}
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
        {incident.assigned_to ? (mine ? t("assignedYou") : t("assignedOther")) : t("unassigned")}
      </span>
      {canAct && !mine && user && (
        <button className="btn" type="button" disabled={assign.isPending} onClick={() => assign.mutate(user.id)}>
          {t("assignMe")}
        </button>
      )}
      {canAct && incident.assigned_to && (
        <button className="btn quiet" type="button" disabled={assign.isPending} onClick={() => assign.mutate(null)}>
          {t("unassign")}
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
        <Link to="/incidents" className="back-link">
          <ArrowLeft size={14} aria-hidden="true" />
          {t("allIncidents")}
        </Link>
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
                    {INCIDENT_STATUS[incident.status]} · {TIER_LABEL[incident.tier] ?? incident.tier}
                    {t("opened", { ago: opened ? formatAgo(opened) : "—" })}
                    {opened ? ` (${formatDateTime(opened, utc)})` : ""}
                    {closed ? t("closedAt", { at: formatDateTime(closed, utc) }) : ""}
                    {incident.source_alert_id ? t("fromAlert") : ""}
                  </p>
                </div>
              </div>

              <section className="card" style={{ marginBottom: 16 }}>
                <Lifecycle status={incident.status} />
              </section>

              <div className="page-grid">
                <div className="grid">
                  <section className="card">
                    <h2>{t("description")}</h2>
                    <p style={{ whiteSpace: "pre-wrap" }}>{incident.description}</p>
                    {incident.closure_summary && (
                      <>
                        <h2>{t("closure")}</h2>
                        <p style={{ whiteSpace: "pre-wrap" }}>{incident.closure_summary}</p>
                      </>
                    )}
                  </section>
                  <Recommendations incident={incident} />
                  <section className="card">
                    <h2>{t("timeline")}</h2>
                    <p className="muted" style={{ marginTop: 0 }}>
                      {t("timelineNote")}
                    </p>
                    <Timeline events={incident.timeline} />
                  </section>
                </div>

                <aside className="grid">
                  <section className="card detail">
                    <section>
                      <h3>{t("status")}</h3>
                      {canAct ? (
                        <Transitions incident={incident} />
                      ) : (
                        <p className="reason" style={{ textAlign: "left" }}>
                          {t("statusRolesOnly")}
                        </p>
                      )}
                    </section>
                    <section>
                      <h3>{t("tier")}</h3>
                      <Escalation incident={incident} canAct={canAct} />
                    </section>
                    <section>
                      <h3>{t("assignment")}</h3>
                      <Assignment incident={incident} canAct={canAct} />
                    </section>
                    {canAct && (
                      <section>
                        <h3>{t("addToTimeline")}</h3>
                        <NoteForm incident={incident} />
                      </section>
                    )}
                  </section>
                  <section className="card detail">
                    <AttackSection context={incident.attack} />
                  </section>
                  <section className="card detail">
                    <section>
                      <h3>{t("huntSection")}</h3>
                      <IncidentHunting incident={incident} canAct={canAct} />
                    </section>
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
