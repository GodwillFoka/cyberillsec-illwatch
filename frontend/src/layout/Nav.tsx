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
        <span className={`count ${tone}`} aria-label={`${count} à traiter`}>
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
    <nav className="nav" aria-label="Navigation principale">
      <RouterLink to="/" className="nav-brand" aria-label="ILL Watch, vue d'ensemble">
        <Lockup />
      </RouterLink>
      <div className="nav-group">
        <Link to="/" label="Vue d'ensemble" icon={LayoutDashboard} />
      </div>
      <div className="nav-group" role="group" aria-labelledby="nav-soc">
        <div className="nav-section" id="nav-soc">
          Opérations SOC
        </div>
        <Link to="/triage" label="Triage" icon={Siren} count={summary?.alerts.unacknowledged} />
        <Link to="/incidents" label="Incidents" icon={ShieldAlert} count={summary?.incidents.open} />
        <Link to="/pilotage" label="Pilotage" icon={Gauge} />
      </div>
      <div className="nav-group" role="group" aria-labelledby="nav-cti">
        <div className="nav-section" id="nav-cti">
          Renseignement
        </div>
        <Link to="/indicateurs" label="Indicateurs" icon={Fingerprint} />
        <Link to="/campagnes" label="Campagnes" icon={Flag} />
        <Link
          to="/sources"
          label="Sources CTI"
          icon={RadioTower}
          count={summary?.feeds.degraded.length}
          tone="p0"
        />
      </div>
      <div className="nav-group" role="group" aria-labelledby="nav-vuln">
        <div className="nav-section" id="nav-vuln">
          Vulnérabilités
        </div>
        <Link to="/cve" label="CVE et priorités" icon={Bug} />
      </div>
      <div className="nav-group" role="group" aria-labelledby="nav-detect">
        <div className="nav-section" id="nav-detect">
          Détection
        </div>
        <Link
          to="/correlations"
          label="Corrélations"
          icon={GitMerge}
          count={summary?.correlations.open}
          tone={
            summary && (summary.correlations.open_by_priority.P0_CRITIQUE ?? 0) > 0 ? "p0" : "p1"
          }
        />
        <Link to="/chasse" label="Chasse" icon={Crosshair} />
        <Link to="/inventaire" label="Inventaire" icon={Server} />
      </div>
      <div className="nav-spacer" />
      {user?.role === "ADMIN" && (
        <div className="nav-group">
          <Link to="/administration" label="Administration" icon={Settings} />
        </div>
      )}
    </nav>
  );
}
