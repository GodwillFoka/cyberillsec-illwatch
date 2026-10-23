// Barre supérieure (brand book v2) : état du direct dans la voix de la marque (toujours
// visible), pause, heure « UTC · 08:02:17 » ou locale, compte.
import { LogOut, Pause, Play } from "lucide-react";
import { useEffect, useState } from "react";

import { useAuth } from "../auth/AuthProvider";
import { LanguageSelect } from "../i18n/LanguageSelect";
import { formatTime } from "../lib/format";
import { useTimeZone } from "../lib/time";
import { ROLE_LABEL } from "../lib/levels";
import { useRealtime } from "../realtime/RealtimeProvider";
import { shell } from "./shell.i18n";

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
      ? shell.plural("pausedPending", pending)
      : shell("paused")
    : status === "live"
      ? shell("live")
      : status === "connecting"
        ? shell("connecting")
        : shell("interrupted");

  return (
    <header className="topbar">
      <span className={`live-chip ${state}`} role="status" aria-live="polite" title={label}>
        <span className="live-text">{label}</span>
      </span>
      <button
        className="btn quiet icon-btn"
        type="button"
        onClick={togglePause}
        aria-label={paused ? shell("resume") : shell("pause")}
        title={paused ? shell("resume") : shell("pause")}
      >
        {paused ? (
          <Play size={20} strokeWidth={1.5} aria-hidden="true" />
        ) : (
          <Pause size={20} strokeWidth={1.5} aria-hidden="true" />
        )}
        <span className="hide-narrow">{paused ? shell("resume") : shell("pause")}</span>
      </button>
      <span className="grow" />
      <button
        className="btn quiet clock"
        type="button"
        onClick={toggle}
        title={shell("clockToggle")}
      >
        <span className="clock-zone">{utc ? "UTC" : shell("local")}</span>
        <span className="clock-sep" aria-hidden="true">
          ·
        </span>
        <Clock utc={utc} />
      </button>
      <LanguageSelect compact />
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
        aria-label={shell("signOut")}
        title={shell("signOut")}
      >
        <LogOut size={20} strokeWidth={1.5} aria-hidden="true" />
      </button>
    </header>
  );
}
