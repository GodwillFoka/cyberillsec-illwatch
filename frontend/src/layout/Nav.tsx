// Menu latéral (brand book v2) : symbole 32 px et « ILL Watch / PAR CYBERILL », sections en
// capitales espacées, icônes Lucide 20 px trait 1,5 en muted, élément actif indigo avec repère
// orange de 3 px. Les compteurs n'apparaissent que s'il y a quelque chose à traiter.
import {
  Bug,
  Crosshair,
  Fingerprint,
  Flag,
  Gauge,
  GitMerge,
  LayoutDashboard,
  RadioTower,
  Server,
  Settings,
  ShieldAlert,
  Siren,
  type LucideIcon,
} from "lucide-react";

import { useSummary } from "../api/queries";
import { useAuth } from "../auth/AuthProvider";
import { Lockup } from "../components/Logo";
import { shell } from "./shell.i18n";
import { Link as RouterLink, isActive, useLocation } from "../lib/router";

interface Item {
  to: string;
  label: string;
  icon: LucideIcon;
  count?: number;
  tone?: "p0" | "p1";
}

function Link({ to, label, icon: Icon, count, tone = "p1" }: Item) {
  const { pathname } = useLocation();
  const active = isActive(pathname, to);
  return (
    <RouterLink
      to={to}
      aria-current={active ? "page" : undefined}
      className={`nav-link${active ? " active" : ""}`}
    >
      <Icon className="nav-icon" size={20} strokeWidth={1.5} aria-hidden="true" />
      <span className="nav-label">{label}</span>
      {count ? (
        <span className={`count ${tone}`} aria-label={shell("toProcess", { count })}>
          {count > 999 ? "999+" : count}
        </span>
      ) : null}
    </RouterLink>
  );
}

export function Nav() {
  const summary = useSummary().data;
  const { user } = useAuth();
  return (
    <nav className="nav" aria-label={shell("navLabel")}>
      <RouterLink to="/" className="nav-brand" aria-label={shell("brandHome")}>
        <Lockup />
      </RouterLink>
      <div className="nav-group">
        <Link to="/" label={shell("overview")} icon={LayoutDashboard} />
      </div>
      <div className="nav-group" role="group" aria-labelledby="nav-soc">
        <div className="nav-section" id="nav-soc">
          {shell("secSoc")}
        </div>
        <Link to="/triage" label={shell("triage")} icon={Siren} count={summary?.alerts.unacknowledged} />
        <Link to="/incidents" label={shell("incidents")} icon={ShieldAlert} count={summary?.incidents.open} />
        <Link to="/pilotage" label={shell("pilotage")} icon={Gauge} />
      </div>
      <div className="nav-group" role="group" aria-labelledby="nav-cti">
        <div className="nav-section" id="nav-cti">
          {shell("secIntel")}
        </div>
        <Link to="/indicateurs" label={shell("indicators")} icon={Fingerprint} />
        <Link to="/campagnes" label={shell("campaigns")} icon={Flag} />
        <Link
          to="/sources"
          label={shell("sources")}
          icon={RadioTower}
          count={summary?.feeds.degraded.length}
          tone="p0"
        />
      </div>
      <div className="nav-group" role="group" aria-labelledby="nav-vuln">
        <div className="nav-section" id="nav-vuln">
          {shell("secVuln")}
        </div>
        <Link to="/cve" label={shell("cves")} icon={Bug} />
      </div>
      <div className="nav-group" role="group" aria-labelledby="nav-detect">
        <div className="nav-section" id="nav-detect">
          {shell("secDetect")}
        </div>
        <Link
          to="/correlations"
          label={shell("correlations")}
          icon={GitMerge}
          count={summary?.correlations.open}
          tone={
            summary && (summary.correlations.open_by_priority.P0_CRITIQUE ?? 0) > 0 ? "p0" : "p1"
          }
        />
        <Link to="/chasse" label={shell("hunting")} icon={Crosshair} />
        <Link to="/inventaire" label={shell("inventory")} icon={Server} />
      </div>
      <div className="nav-spacer" />
      {user?.role === "ADMIN" && (
        <div className="nav-group">
          <Link to="/administration" label={shell("admin")} icon={Settings} />
        </div>
      )}
    </nav>
  );
}
