// Langue de l'interface : choisie au démarrage (detect.ts), modifiable par le sélecteur.
// Changer de langue remonte l'application sous la session (AuthProvider reste monté : la
// session et le cache des requêtes sont conservés) afin que chaque texte soit retraduit.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import { currentLang, setCurrentLang, type Lang } from "./core";
import { fetchServerLanguage, pickLanguage, readSaved, saveChoice } from "./detect";

interface LanguageValue {
  lang: Lang;
  setLang: (lang: Lang) => void;
}

const LanguageContext = createContext<LanguageValue>({ lang: "fr", setLang: () => undefined });

function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/** Détermine la langue avant le premier rendu (aucun texte n'apparaît dans la mauvaise langue). */
export async function bootLanguage(): Promise<Lang> {
  const saved = readSaved(storage());
  const languages = navigator.languages?.length ? navigator.languages : [navigator.language];
  const server = saved ? null : await fetchServerLanguage();
  const lang = pickLanguage({ saved, server, languages });
  setCurrentLang(lang);
  return lang;
}

export function LanguageProvider({ children }: { children: (lang: Lang) => ReactNode }) {
  const [lang, setLangState] = useState<Lang>(currentLang());

  const setLang = useCallback((next: Lang) => {
    saveChoice(storage(), next);
    setCurrentLang(next);
    setLangState(next);
  }, []);

  // Un autre onglet a changé de langue : on suit.
  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key === "illwatch.lang" && event.newValue && event.newValue !== currentLang()) {
        const next = event.newValue as Lang;
        if (["fr", "en", "de", "es", "zh"].includes(next)) {
          setCurrentLang(next);
          setLangState(next);
        }
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const value = useMemo(() => ({ lang, setLang }), [lang, setLang]);
  return <LanguageContext.Provider value={value}>{children(lang)}</LanguageContext.Provider>;
}

export function useLanguage(): LanguageValue {
  return useContext(LanguageContext);
}
