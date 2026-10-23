// Adresse racine « / » : choisit la langue puis redirige vers /<langue>/ (ADR-027).
// Sans JavaScript, la page affiche simplement la liste des langues.
import { COUNTRY_LANGUAGES } from "./countries.js";
import { pickLanguage, readSaved, SUPPORTED } from "./lang.js";

const root = document.documentElement;
const base = root.dataset.base || "/";
const endpoint = root.dataset.geo || "";
const instanceLang = root.dataset.instanceLang || null;

function go(lang) {
  window.location.replace(base + lang + "/" + window.location.hash);
}

/** Langue décidée par le serveur (pays de l'adresse IP), ou null s'il ne répond pas vite. */
async function serverLang() {
  if (!endpoint) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1200);
  try {
    const response = await fetch(endpoint, {
      signal: controller.signal,
      credentials: "omit",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return null;
    const body = await response.json();
    return typeof body.lang === "string" && SUPPORTED.includes(body.lang) ? body.lang : null;
  } catch {
    return null; // serveur absent, lent ou réponse invalide : décision locale
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
  timeZone,
  languages: navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language],
  instanceLang,
  countries: COUNTRY_LANGUAGES,
};

if (signals.saved && SUPPORTED.includes(signals.saved)) {
  go(signals.saved); // le choix du visiteur l'emporte : aucune requête
} else {
  serverLang().then((lang) => go(pickLanguage({ ...signals, serverLang: lang })));
}
