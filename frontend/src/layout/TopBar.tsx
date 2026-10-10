import { useEffect, useState } from "react";

import { useAuth } from "../auth/AuthProvider";
import { formatTime } from "../lib/format";
import { useTimeZone } from "../lib/time";
import { useRealtime } from "../realtime/RealtimeProvider";

function Clock({ utc }: { utc: boolean }) {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  return <span className="mono">{formatTime(now, utc, true)}</span>;
}

export function TopBar() {
  const { status, paused, pending, togglePause } = useRealtime();
  const { utc, toggle } = useTimeZone();
  const { user, signOut } = useAuth();

  const state = paused ? "paused" : status;
  const label = paused
    ? pending > 0
      ? `Direct en pause · ${pending} mise${pending > 1 ? "s" : ""} à jour en attente`
      : "Direct en pause"
    : status === "live"
      ? "Connecté · en direct"
      : status === "connecting"
        ? "Connexion au direct…"
        : "Direct interrompu · nouvel essai, données relues chaque minute";

  return (
    <header className="topbar">
      <span className="live" role="status" aria-live="polite">
        <span className={`dot ${state}`} aria-hidden="true" />
        {label}
      </span>
      <button className="btn quiet" type="button" aria-pressed={paused} onClick={togglePause}>
        {paused ? "Reprendre le direct" : "Mettre en pause"}
      </button>
      <span className="grow" />
      <button
        className="btn quiet"
        type="button"
        onClick={toggle}
        title="Basculer entre UTC et l'heure locale"
      >
        {utc ? "UTC" : "Local"} · <Clock utc={utc} />
      </button>
      {user && (
        <span className="muted" title={user.email}>
          {user.username} · {user.role}
        </span>
      )}
      <button className="btn" type="button" onClick={() => void signOut()}>
        Se déconnecter
      </button>
    </header>
  );
}
