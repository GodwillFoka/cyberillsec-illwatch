// Sélecteur de langue : liste native (accessible au clavier et aux lecteurs d'écran), chaque
// langue écrite dans sa propre langue. Un choix l'emporte ensuite sur toute détection.
import { Languages } from "lucide-react";

import { LANGS, LANGUAGE_NAMES, isLang } from "./core";
import { messages } from "./common.i18n";
import { useLanguage } from "./LanguageProvider";

export function LanguageSelect({ compact = false }: { compact?: boolean }) {
  const { lang, setLang } = useLanguage();
  return (
    <label className={`lang-select${compact ? " compact" : ""}`} title={messages("language")}>
      <Languages size={18} strokeWidth={1.5} aria-hidden="true" />
      <span className="sr-only">{messages("language")}</span>
      <select
        value={lang}
        onChange={(event) => {
          if (isLang(event.target.value)) setLang(event.target.value);
        }}
      >
        {LANGS.map((code) => (
          <option key={code} value={code} lang={code === "zh" ? "zh-Hans" : code}>
            {compact ? code.toUpperCase() : LANGUAGE_NAMES[code]}
          </option>
        ))}
      </select>
    </label>
  );
}
