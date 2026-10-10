import { BrowserRouter, Route, Routes } from "react-router-dom";

import { useAuth } from "./auth/AuthProvider";
import { LoginPage } from "./auth/LoginPage";
import { Shell } from "./layout/Shell";
import { Overview } from "./pages/Overview";
import { NotFound, Upcoming } from "./pages/Upcoming";

const UPCOMING: [string, string, string][] = [
  ["triage/*", "Triage", "Alertes à qualifier, acquitter ou transformer en incident."],
  ["incidents/*", "Incidents", "Suivi des incidents, de l'ouverture à la clôture."],
  ["indicateurs/*", "Indicateurs (IOC)", "Recherche et détail des indicateurs de compromission."],
  ["sources/*", "Sources CTI", "Santé et historique de collecte de chaque source."],
  ["cve/*", "CVE et priorités", "Vulnérabilités classées par priorité de remédiation."],
  ["chasse/*", "Chasse", "Sessions de chasse, règles et correspondances."],
  ["administration/*", "Administration", "Comptes, journal d'audit et paramètres."],
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
    <BrowserRouter>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={<Overview />} />
          {UPCOMING.map(([path, title, description]) => (
            <Route
              key={path}
              path={path}
              element={<Upcoming title={title} description={description} />}
            />
          ))}
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
