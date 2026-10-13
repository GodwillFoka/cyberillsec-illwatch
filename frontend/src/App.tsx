// Les écrans sont chargés à la demande : l'écran de connexion n'attend ni les graphiques
// (ECharts) ni les écrans qu'il n'affiche pas ; chaque écran est un fichier mis en cache à part.
import { lazy, Suspense } from "react";

import { useAuth } from "./auth/AuthProvider";
import { LoginPage } from "./auth/LoginPage";
import { Shell } from "./layout/Shell";
import { isActive, Router, useLocation } from "./lib/router";

const Overview = lazy(() => import("./pages/Overview").then((m) => ({ default: m.Overview })));
const Triage = lazy(() => import("./pages/Triage").then((m) => ({ default: m.Triage })));
const Indicators = lazy(() => import("./pages/Indicators").then((m) => ({ default: m.Indicators })));
const Cves = lazy(() => import("./pages/Cves").then((m) => ({ default: m.Cves })));
const Hunting = lazy(() => import("./pages/Hunting").then((m) => ({ default: m.Hunting })));
const Incidents = lazy(() => import("./pages/Incidents").then((m) => ({ default: m.Incidents })));
const Sources = lazy(() => import("./pages/Sources").then((m) => ({ default: m.Sources })));
const Admin = lazy(() => import("./pages/Admin").then((m) => ({ default: m.Admin })));
const Correlations = lazy(() => import("./pages/Correlations").then((m) => ({ default: m.Correlations })));
const Inventory = lazy(() => import("./pages/Inventory").then((m) => ({ default: m.Inventory })));
const NotFound = lazy(() => import("./pages/NotFound").then((m) => ({ default: m.NotFound })));
const IncidentPage = lazy(() => import("./pages/IncidentPage").then((m) => ({ default: m.IncidentPage })));

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
        <Suspense fallback={<p className="empty">Chargement…</p>}>
          <Screen />
        </Suspense>
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
  if (pathname === "/chasse") return <Hunting />;
  if (pathname === "/correlations") return <Correlations />;
  if (pathname === "/inventaire") return <Inventory />;
  if (pathname === "/incidents") return <Incidents />;
  const incident = /^\/incidents\/([0-9a-f-]{36})$/i.exec(pathname);
  if (incident) return <IncidentPage key={incident[1]} incidentId={incident[1]} />;
  if (pathname === "/sources") return <Sources />;
  if (pathname === "/administration") return <Admin />;
  return <NotFound />;
}
