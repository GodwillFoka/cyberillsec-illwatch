import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "./styles/base.css";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { ApiError } from "./api/http";
import { App } from "./App";
import { AuthProvider } from "./auth/AuthProvider";
import { bootLanguage, LanguageProvider } from "./i18n/LanguageProvider";
import { TimeProvider } from "./lib/time";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false, // le flux temps réel signale les changements
      retry: (failures, error) =>
        !(error instanceof ApiError && error.status >= 400 && error.status < 500) && failures < 2,
    },
  },
});

const root = document.getElementById("root");
if (!root) throw new Error("#root introuvable");

// La langue est connue avant le premier rendu (ADR-027) : aucun texte n'apparaît d'abord dans
// une autre langue. Changer de langue remonte <App> sous la session, qui reste ouverte.
void bootLanguage().then(() =>
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <TimeProvider>
            <LanguageProvider>{(lang) => <App key={lang} />}</LanguageProvider>
          </TimeProvider>
        </AuthProvider>
      </QueryClientProvider>
    </StrictMode>,
  ),
);
