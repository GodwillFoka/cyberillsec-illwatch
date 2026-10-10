import { useAuth } from "./auth/AuthProvider";
import { LoginPage } from "./auth/LoginPage";
import { Shell } from "./layout/Shell";
import { isActive, Router, useLocation } from "./lib/router";
import { Overview } from "./pages/Overview";
import { IncidentPage } from "./pages/IncidentPage";
import { Cves } from "./pages/Cves";
import { Incidents } from "./pages/Incidents";
import { Indicators } from "./pages/Indicators";
import { Triage } from "./pages/Triage";
import { NotFound, Upcoming } from "./pages/Upcoming";

const UPCOMING: [string, string, string][] = [
  ["/sources", "Sources CTI", "Santé et historique de collecte de chaque source."],
  ["/chasse", "Chasse", "Sessions de chasse, règles et correspondances."],
  ["/administration", "Administration", "Comptes, journal d'audit et paramètres."],
];

export function App() {
  const { status } = useAuth();
  if (status === "loading") {
    return <p className="empty">Reprise de la session…</p>;
  }
  if (status === "anonymous") {
    return <LoginPage />;
  }
  return (
    <Router>
      <Shell>
        <Screen />
      </Shell>
    </Router>
  );
}

function Screen() {
  const { pathname } = useLocation();
  if (pathname === "/") return <Overview />;
  if (isActive(pathname, "/triage")) return <Triage />;
  if (pathname === "/indicateurs") return <Indicators />;
  if (pathname === "/cve") return <Cves />;
  if (pathname === "/incidents") return <Incidents />;
  const incident = /^\/incidents\/([0-9a-f-]{36})$/i.exec(pathname);
  if (incident) return <IncidentPage key={incident[1]} incidentId={incident[1]} />;
  const upcoming = UPCOMING.find(([path]) => isActive(pathname, path));
  if (upcoming) return <Upcoming title={upcoming[1]} description={upcoming[2]} />;
  return <NotFound />;
}
