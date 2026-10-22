// Choix de la langue à la première visite (ADR-027, décision 3) — fonctions pures, testées par
// tests/lang.test.mjs. Ordre : choix mémorisé → langue du navigateur → pays → langue par défaut.

export const SUPPORTED = ["fr", "en", "de", "es", "zh"];
export const DEFAULT_LANG = "en";
export const STORAGE_KEY = "illwatch.lang";

/** Première langue prise en charge dans une liste d'étiquettes BCP 47 (« de-AT », « zh-Hant-TW »…). */
export function matchLanguage(tags) {
  for (const tag of tags || []) {
    if (typeof tag !== "string") continue;
    const primary = tag.trim().toLowerCase().split(/[-_]/)[0];
    if (SUPPORTED.includes(primary)) return primary;
  }
  return null;
}

// Fuseau horaire → langue : signal de pays utilisé tant que le site est statique (aucune
// adresse IP n'est alors connue). Les fuseaux absents donnent l'anglais.
const TZ_LANG = {
  fr: [
    "Europe/Paris", "Europe/Brussels", "Europe/Luxembourg", "Europe/Monaco",
    "America/Martinique", "America/Guadeloupe", "America/Cayenne", "Indian/Reunion",
    "Indian/Mayotte", "Pacific/Noumea", "Pacific/Tahiti", "America/Port-au-Prince",
    "Africa/Douala", "Africa/Abidjan", "Africa/Dakar", "Africa/Libreville", "Africa/Kinshasa",
    "Africa/Lubumbashi", "Africa/Brazzaville", "Africa/Bamako", "Africa/Ouagadougou",
    "Africa/Niamey", "Africa/Ndjamena", "Africa/Lome", "Africa/Porto-Novo", "Africa/Bangui",
    "Africa/Conakry", "Africa/Bujumbura", "Africa/Djibouti",
    "Indian/Antananarivo", "Indian/Comoro", "Africa/Algiers", "Africa/Tunis",
    "Africa/Casablanca", "Africa/Nouakchott",
  ],
  de: ["Europe/Berlin", "Europe/Busingen", "Europe/Vienna", "Europe/Zurich", "Europe/Vaduz"],
  es: [
    "Europe/Madrid", "Atlantic/Canary", "Africa/Ceuta", "America/Mexico_City", "America/Cancun",
    "America/Merida", "America/Monterrey", "America/Chihuahua", "America/Hermosillo",
    "America/Mazatlan", "America/Tijuana", "America/Bogota", "America/Lima", "America/Santiago",
    "America/Caracas", "America/Montevideo", "America/Asuncion", "America/La_Paz",
    "America/Guayaquil", "America/Panama", "America/Costa_Rica", "America/Guatemala",
    "America/Tegucigalpa", "America/Managua", "America/El_Salvador", "America/Havana",
    "America/Santo_Domingo", "America/Puerto_Rico", "Africa/Malabo",
  ],
  zh: ["Asia/Shanghai", "Asia/Urumqi", "Asia/Chongqing", "Asia/Harbin", "Asia/Hong_Kong", "Asia/Macau", "Asia/Taipei"],
};

export function langFromTimeZone(timeZone) {
  if (typeof timeZone !== "string" || !timeZone) return null;
  if (timeZone.startsWith("America/Argentina/")) return "es";
  for (const [lang, zones] of Object.entries(TZ_LANG)) {
    if (zones.includes(timeZone)) return lang;
  }
  return null;
}

/**
 * Langue à afficher.
 * @param {{saved?: string|null, languages?: string[], countryLang?: string|null, timeZone?: string|null}} signals
 */
export function pickLanguage({ saved = null, languages = [], countryLang = null, timeZone = null } = {}) {
  if (saved && SUPPORTED.includes(saved)) return saved;
  const fromBrowser = matchLanguage(languages);
  if (fromBrowser) return fromBrowser;
  if (countryLang && SUPPORTED.includes(countryLang)) return countryLang;
  return langFromTimeZone(timeZone) || DEFAULT_LANG;
}

export function readSaved(storage) {
  try {
    return storage ? storage.getItem(STORAGE_KEY) : null;
  } catch {
    return null; // stockage refusé (navigation privée, données bloquées)
  }
}

export function saveChoice(storage, lang) {
  try {
    if (storage && SUPPORTED.includes(lang)) storage.setItem(STORAGE_KEY, lang);
  } catch {
    /* le choix n'est simplement pas mémorisé */
  }
}
