import { useAuth } from "./auth/AuthProvider";
import { LoginPage } from "./auth/LoginPage";
import { Shell } from "./layout/Shell";
import { isActive, Router, useLocation } from "./lib/router";
import { Overview } from "./pages/Overview";
import { NotFound, Upcoming } from "./pages/Upcoming";

const UPCOMING: [string, string, string][] = [
  ["/triage", "Triage", "Alertes à qualifier, acquitter ou transformer en incident."],
  ["/incidents", "Incidents", "Suivi des incidents, de l'ouverture à la clôture."],
  ["/indicateurs", "Indicateurs (IOC)", "Recherche et détail des indicateurs de compromission."],
  ["/sources", "Sources CTI", "Santé et historique de collecte de chaque source."],
  ["/cve", "CVE et priorités", "Vulnérabilités classées par priorité de remédiation."],
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
  const upcoming = UPCOMING.find(([path]) => isActive(pathname, path));
  if (upcoming) return <Upcoming title={upcoming[1]} description={upcoming[2]} />;
  return <NotFound />;
}
