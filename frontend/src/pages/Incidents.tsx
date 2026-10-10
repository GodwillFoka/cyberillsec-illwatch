// Incidents : liste (les plus graves d'abord) et ouverture manuelle d'un incident.
import { useState, type FormEvent } from "react";

import { useCreateIncident } from "../api/mutations";
import { useIncidents, type IncidentFilters } from "../api/queries";
import { useAuth } from "../auth/AuthProvider";
import { LevelBadge } from "../components/Badge";
import { QueryState } from "../components/QueryState";
import { formatAge, formatNumber, parseDate } from "../lib/format";
import { INCIDENT_STATUS, SEVERITY_ORDER, levelLabel } from "../lib/levels";
import { Link, useLocation } from "../lib/router";
import { useFresh } from "../lib/useFresh";

export const RESPONDER_ROLES = new Set(["ADMIN", "ANALYST"]);
const STATUSES = ["NOUVEAU", "ANALYSE", "CONFINEMENT", "ERADICATION", "RECUPERATION", "CLOTURE"];

function NewIncidentForm({ onClose }: { onClose: () => void }) {
  const create = useCreateIncident();
  const { navigate } = useLocation();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("HIGH");

  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate(
      { title: title.trim(), description: description.trim(), severity },
      { onSuccess: (incident) => navigate(`/incidents/${incident.id}`) },
    );
  }

  return (
    <form className="card form" onSubmit={submit} aria-labelledby="nouvel-incident">
      <h2 id="nouvel-incident">Ouvrir un incident</h2>
      <label className="field">
        Titre
        <input required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
      </label>
      <label className="field">
        Description (constat initial, périmètre, source de l'information)
        <textarea
          required
          maxLength={20000}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </label>
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
      {create.error && (
        <p className="notice error" role="alert">
          Création refusée : {create.error.message}
        </p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          Annuler
        </button>
        <button className="btn primary" type="submit" disabled={create.isPending}>
          {create.isPending ? "Ouverture…" : "Ouvrir l'incident"}
        </button>
      </div>
    </form>
  );
}

export function Incidents() {
  const { user } = useAuth();
  const canAct = user ? RESPONDER_ROLES.has(user.role) : false;
  const [filters, setFilters] = useState<IncidentFilters>({ openOnly: true });
  const [creating, setCreating] = useState(false);
  const query = useIncidents(filters);
  const fresh = useFresh(query.data?.items.map((i) => `${i.id}:${i.updated_at}`));

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Incidents</h1>
          <p>Du signalement à la clôture, selon le cycle NIST SP 800-61</p>
        </div>
        {canAct && !creating && (
          <button className="btn primary" type="button" onClick={() => setCreating(true)}>
            Nouvel incident
          </button>
        )}
      </div>

      {creating && (
        <div style={{ marginBottom: 16 }}>
          <NewIncidentForm onClose={() => setCreating(false)} />
        </div>
      )}

      <section className="card">
        <div className="toolbar">
          <span className="muted">
            {query.data
              ? `${formatNumber(query.data.total)} incident${query.data.total > 1 ? "s" : ""}${filters.openOnly ? " ouvert" + (query.data.total > 1 ? "s" : "") : ""}`
              : " "}
          </span>
          <div className="row">
            <div className="seg" role="group" aria-label="Périmètre">
              <button
                type="button"
                aria-pressed={filters.openOnly}
                onClick={() => setFilters((f) => ({ ...f, openOnly: true, status: undefined }))}
              >
                Ouverts
              </button>
              <button
                type="button"
                aria-pressed={!filters.openOnly}
                onClick={() => setFilters((f) => ({ ...f, openOnly: false }))}
              >
                Tous
              </button>
            </div>
            <select
              className="compact"
              aria-label="Statut"
              value={filters.status ?? ""}
              onChange={(e) =>
                setFilters((f) => ({
                  ...f,
                  status: e.target.value || undefined,
                  openOnly: e.target.value === "CLOTURE" ? false : f.openOnly,
                }))
              }
            >
              <option value="">Tous les statuts</option>
              {STATUSES.map((status) => (
                <option key={status} value={status}>
                  {INCIDENT_STATUS[status]}
                </option>
              ))}
            </select>
            <select
              className="compact"
              aria-label="Sévérité"
              value={filters.severity ?? ""}
              onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value || undefined }))}
            >
              <option value="">Toutes sévérités</option>
              {SEVERITY_ORDER.map((level) => (
                <option key={level} value={level}>
                  {levelLabel(level)}
                </option>
              ))}
            </select>
          </div>
        </div>
        <QueryState query={query} empty={(page) => page.items.length === 0}>
          {(page) => (
            <table className="table">
              <thead>
                <tr>
                  <th>Sévérité</th>
                  <th>Incident</th>
                  <th>Statut</th>
                  <th>Assigné</th>
                  <th>Ouvert</th>
                  <th>Dernière activité</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((incident) => {
                  const opened = parseDate(incident.created_at);
                  const updated = parseDate(incident.updated_at);
                  return (
                    <tr
                      key={incident.id}
                      className={fresh.has(`${incident.id}:${incident.updated_at}`) ? "fresh" : undefined}
                    >
                      <td>
                        <LevelBadge level={incident.severity} />
                      </td>
                      <td className="ellipsis" style={{ maxWidth: 420 }}>
                        <Link to={`/incidents/${incident.id}`} title={incident.title}>
                          {incident.title}
                        </Link>
                      </td>
                      <td>{INCIDENT_STATUS[incident.status] ?? incident.status}</td>
                      <td className="muted">
                        {incident.assigned_to
                          ? incident.assigned_to === user?.id
                            ? "vous"
                            : "un analyste"
                          : "personne"}
                      </td>
                      <td className="muted">{opened ? `il y a ${formatAge(opened)}` : "—"}</td>
                      <td className="muted">{updated ? `il y a ${formatAge(updated)}` : "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </QueryState>
      </section>
    </>
  );
}
