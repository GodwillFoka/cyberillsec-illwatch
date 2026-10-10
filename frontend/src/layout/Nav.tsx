import { NavLink } from "react-router-dom";

import { useSummary } from "../api/queries";
import { Logo } from "../components/Logo";

interface Item {
  to: string;
  label: string;
  count?: number;
  soon?: boolean;
}

function Link({ to, label, count, soon }: Item) {
  return (
    <NavLink
      to={to}
      end={to === "/"}
      className={({ isActive }) => `nav-link${isActive ? " active" : ""}${soon ? " soon" : ""}`}
    >
      <span>{label}</span>
      {count ? (
        <span className="count" aria-label={`${count} à traiter`}>
          {count}
        </span>
      ) : null}
    </NavLink>
  );
}

export function Nav() {
  const summary = useSummary().data;
  return (
    <nav className="nav" aria-label="Navigation principale">
      <div className="nav-brand">
        <Logo />
        <div>
          <strong>ILLWATCH</strong>
          <small>BY CYBERILLSEC</small>
        </div>
      </div>
      <Link to="/" label="Vue d'ensemble" />
      <div className="nav-section">Opérations SOC</div>
      <Link to="/triage" label="Triage" count={summary?.alerts.unacknowledged} soon />
      <Link to="/incidents" label="Incidents" count={summary?.incidents.open} soon />
      <div className="nav-section">Renseignement</div>
      <Link to="/indicateurs" label="Indicateurs (IOC)" soon />
      <Link to="/sources" label="Sources CTI" count={summary?.feeds.degraded.length} soon />
      <div className="nav-section">Vulnérabilités</div>
      <Link to="/cve" label="CVE et priorités" soon />
      <div className="nav-section">Chasse</div>
      <Link to="/chasse" label="Recherches et règles" soon />
      <div className="nav-spacer" />
      <div className="nav-section">Administration</div>
      <Link to="/administration" label="Comptes, audit, paramètres" soon />
    </nav>
  );
}
