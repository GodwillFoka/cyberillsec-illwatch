// Associer un IOC ou une CVE à un incident ouvert (RF-20), depuis leur fiche.
import { useEffect, useState, type FormEvent } from "react";

import { useAttachToIncident, type AttachTarget } from "../api/mutations";
import { useOpenIncidents } from "../api/queries";
import { levelLabel } from "../lib/levels";
import { Link } from "../lib/router";

export function AttachToIncident({ target, label }: { target: AttachTarget; label: string }) {
  const open = useOpenIncidents(50);
  const attach = useAttachToIncident();
  const [incidentId, setIncidentId] = useState("");
  const [result, setResult] = useState<{ id: string; created: boolean } | null>(null);
  const key = "indicatorId" in target ? target.indicatorId : target.cveId;

  useEffect(() => {
    setResult(null);
    attach.reset();
  }, [key]);

  const incidents = open.data?.items ?? [];
  if (open.isSuccess && incidents.length === 0) {
    return <p className="muted">Aucun incident ouvert auquel l'associer.</p>;
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!incidentId) return;
    attach.mutate(
      { incidentId, target },
      { onSuccess: (body) => setResult({ id: incidentId, created: body.created }) },
    );
  }

  return (
    <form className="form" onSubmit={submit}>
      <label className="field">
        Associer {label} à un incident ouvert
        <select value={incidentId} onChange={(e) => setIncidentId(e.target.value)} required>
          <option value="">Choisir…</option>
          {incidents.map((incident) => (
            <option key={incident.id} value={incident.id}>
              [{levelLabel(incident.severity)}] {incident.title}
            </option>
          ))}
        </select>
      </label>
      {result && (
        <p className="notice ok" role="status">
          {result.created ? "Associé à " : "Déjà associé à "}
          <Link to={`/incidents/${result.id}`}>l'incident</Link> (chronologie mise à jour).
        </p>
      )}
      {attach.error && (
        <p className="notice error" role="alert">
          Association refusée : {attach.error.message}
        </p>
      )}
      <div className="actions">
        <button className="btn primary" type="submit" disabled={!incidentId || attach.isPending}>
          {attach.isPending ? "Association…" : "Associer"}
        </button>
      </div>
    </form>
  );
}
