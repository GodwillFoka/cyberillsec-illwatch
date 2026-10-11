// Barre supérieure (v7) : état du direct (toujours visible), pause, heure UTC/locale, compte.
import { LogOut, Pause, Play } from "lucide-react";
import { useEffect, useState } from "react";

import { useAuth } from "../auth/AuthProvider";
import { formatTime } from "../lib/format";
import { useTimeZone } from "../lib/time";
import { useRealtime } from "../realtime/RealtimeProvider";

const ROLE_LABEL: Record<string, string> = {
  ADMIN: "Administrateur",
  ANALYST: "Analyste",
  VIEWER: "Lecteur",
};

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
      ? `En pause, ${pending} mise${pending > 1 ? "s" : ""} à jour en attente`
      : "En pause"
    : status === "live"
      ? "En direct"
      : status === "connecting"
        ? "Connexion au direct…"
        : "Direct interrompu, relecture chaque minute";

  return (
    <header className="topbar">
      <span className={`live-chip ${state}`} role="status" aria-live="polite">
        <span className={`dot ${state}`} aria-hidden="true" />
        {label}
      </span>
      <button
        className="btn quiet icon-btn"
        type="button"
        aria-pressed={paused}
        onClick={togglePause}
        title={paused ? "Reprendre le direct" : "Mettre le direct en pause"}
      >
        {paused ? <Play size={16} aria-hidden="true" /> : <Pause size={16} aria-hidden="true" />}
        <span className="hide-narrow">{paused ? "Reprendre" : "Pause"}</span>
      </button>
      <span className="grow" />
      <button
        className="btn quiet clock"
        type="button"
        onClick={toggle}
        title="Basculer entre UTC et l'heure locale"
      >
        <span className="clock-zone">{utc ? "UTC" : "Local"}</span>
        <Clock utc={utc} />
      </button>
      {user && (
        <span className="user-chip" title={user.email}>
          <span className="avatar" aria-hidden="true">
            {user.username.slice(0, 2).toUpperCase()}
          </span>
          <span className="hide-narrow">
            <strong>{user.username}</strong>
            <small>{ROLE_LABEL[user.role] ?? user.role}</small>
          </span>
        </span>
      )}
      <button
        className="btn quiet icon-btn"
        type="button"
        onClick={() => void signOut()}
        aria-label="Se déconnecter"
        title="Se déconnecter"
      >
        <LogOut size={16} aria-hidden="true" />
      </button>
    </header>
  );
}
