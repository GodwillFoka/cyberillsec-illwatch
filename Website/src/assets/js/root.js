// Adresse racine « / » : choisit la langue puis redirige vers /<langue>/ (ADR-027).
// Sans JavaScript, la page affiche simplement la liste des langues.
import { matchLanguage, pickLanguage, readSaved, SUPPORTED } from "./lang.js";

const root = document.documentElement;
const base = root.dataset.base || "/";
const endpoint = root.dataset.geo || "";

function go(lang) {
  window.location.replace(base + lang + "/" + window.location.hash);
}

async function countryLang() {
  if (!endpoint) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 800);
  try {
    const response = await fetch(endpoint, { signal: controller.signal, credentials: "omit" });
    if (!response.ok) return null;
    const body = await response.json();
    return SUPPORTED.includes(body.lang) ? body.lang : null;
  } catch {
    return null; // serveur absent ou lent : on passe au signal suivant
  } finally {
    clearTimeout(timer);
  }
}

let timeZone = null;
try {
  timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
} catch {
  timeZone = null;
}

let storage = null;
try {
  storage = window.localStorage; // l'accès lui-même peut lever une exception
} catch {
  storage = null;
}

const signals = {
  saved: readSaved(storage),
  languages: navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language],
  timeZone,
};

// Le pays (adresse IP côté serveur) n'est demandé que si ni un choix mémorisé ni la langue du
// navigateur ne décident.
if ((signals.saved && SUPPORTED.includes(signals.saved)) || matchLanguage(signals.languages)) {
  go(pickLanguage(signals));
} else {
  countryLang().then((lang) => go(pickLanguage({ ...signals, countryLang: lang })));
}
