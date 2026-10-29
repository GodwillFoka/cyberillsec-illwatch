// Choix de la langue à la première visite (ADR-027) : fonctions pures, testées par
// tests/lang.test.mjs. Même ordre que l'API (illwatch/shared/i18n.py) :
//   1. choix mémorisé du visiteur ;
//   2. réponse du serveur (pays de l'adresse IP, navigateur, langue de l'instance) ;
//   3. hors serveur (site statique) : pays déduit du fuseau horaire, le navigateur départageant
//      les pays bilingues ; puis langue du navigateur ; puis langue de l'instance ; puis anglais.
// La table pays → langues (data/country-languages.json) est celle de l'API, vérifiée par test.

export const SUPPORTED = ["fr", "en", "de", "es", "zh"];
export const FALLBACK = "en";
export const STORAGE_KEY = "illwatch.lang";

/** Langues prises en charge, dans l'ordre de préférence d'une liste d'étiquettes BCP 47. */
export function browserLanguages(tags) {
  const out = [];
  for (const tag of tags || []) {
    if (typeof tag !== "string") continue;
    const primary = tag.trim().toLowerCase().split(/[-_]/)[0];
    if (SUPPORTED.includes(primary) && !out.includes(primary)) out.push(primary);
  }
  return out;
}

export function matchLanguage(tags) {
  return browserLanguages(tags)[0] || null;
}

// Fuseau horaire → pays (ISO 3166-1 alpha-2). Seul signal de pays d'une page statique ;
// les fuseaux absents ne donnent aucun pays (la langue du navigateur décide alors).
const TZ_COUNTRY = {
  "Europe/Paris": "FR", "Europe/Monaco": "MC", "Europe/Brussels": "BE", "Europe/Luxembourg": "LU",
  "Europe/Zurich": "CH", "Europe/Berlin": "DE", "Europe/Busingen": "DE", "Europe/Vienna": "AT",
  "Europe/Vaduz": "LI", "Europe/Madrid": "ES", "Atlantic/Canary": "ES", "Africa/Ceuta": "ES",
  "Europe/London": "GB", "Europe/Dublin": "IE",
  "America/Martinique": "MQ", "America/Guadeloupe": "GP", "America/Cayenne": "GF",
  "Indian/Reunion": "RE", "Indian/Mayotte": "YT", "Pacific/Noumea": "NC", "Pacific/Tahiti": "PF",
  "America/Port-au-Prince": "HT", "America/Miquelon": "PM",
  "Africa/Douala": "CM", "Africa/Abidjan": "CI", "Africa/Dakar": "SN", "Africa/Libreville": "GA",
  "Africa/Kinshasa": "CD", "Africa/Lubumbashi": "CD", "Africa/Brazzaville": "CG",
  "Africa/Bamako": "ML", "Africa/Ouagadougou": "BF", "Africa/Niamey": "NE", "Africa/Ndjamena": "TD",
  "Africa/Lome": "TG", "Africa/Porto-Novo": "BJ", "Africa/Bangui": "CF", "Africa/Conakry": "GN",
  "Africa/Bujumbura": "BI", "Africa/Djibouti": "DJ", "Indian/Antananarivo": "MG",
  "Indian/Comoro": "KM", "Africa/Algiers": "DZ", "Africa/Tunis": "TN", "Africa/Casablanca": "MA",
  "Africa/Nouakchott": "MR", "Africa/Malabo": "GQ",
  "Africa/Lagos": "NG", "Africa/Accra": "GH", "Africa/Nairobi": "KE", "Africa/Johannesburg": "ZA",
  "America/Mexico_City": "MX", "America/Cancun": "MX", "America/Merida": "MX",
  "America/Monterrey": "MX", "America/Chihuahua": "MX", "America/Hermosillo": "MX",
  "America/Mazatlan": "MX", "America/Tijuana": "MX", "America/Bogota": "CO", "America/Lima": "PE",
  "America/Santiago": "CL", "America/Caracas": "VE", "America/Montevideo": "UY",
  "America/Asuncion": "PY", "America/La_Paz": "BO", "America/Guayaquil": "EC",
  "America/Panama": "PA", "America/Costa_Rica": "CR", "America/Guatemala": "GT",
  "America/Tegucigalpa": "HN", "America/Managua": "NI", "America/El_Salvador": "SV",
  "America/Havana": "CU", "America/Santo_Domingo": "DO", "America/Puerto_Rico": "PR",
  "America/New_York": "US", "America/Chicago": "US", "America/Denver": "US", "America/Phoenix": "US",
  "America/Los_Angeles": "US", "America/Anchorage": "US", "Pacific/Honolulu": "US",
  "America/Detroit": "US", "America/Toronto": "CA", "America/Montreal": "CA",
  "America/Vancouver": "CA", "America/Edmonton": "CA", "America/Winnipeg": "CA",
  "America/Halifax": "CA", "America/St_Johns": "CA", "America/Regina": "CA",
  "Australia/Sydney": "AU", "Australia/Melbourne": "AU", "Australia/Brisbane": "AU",
  "Australia/Perth": "AU", "Australia/Adelaide": "AU", "Pacific/Auckland": "NZ",
  "Asia/Kolkata": "IN", "Asia/Calcutta": "IN", "Asia/Karachi": "PK", "Asia/Manila": "PH",
  "Asia/Kuala_Lumpur": "MY", "Asia/Singapore": "SG",
  "Asia/Shanghai": "CN", "Asia/Urumqi": "CN", "Asia/Chongqing": "CN", "Asia/Harbin": "CN",
  "Asia/Hong_Kong": "HK", "Asia/Macau": "MO", "Asia/Taipei": "TW",
};

export function countryFromTimeZone(timeZone) {
  if (typeof timeZone !== "string" || !timeZone) return null;
  if (timeZone.startsWith("America/Argentina/")) return "AR";
  if (timeZone.startsWith("America/Indiana/") || timeZone.startsWith("America/Kentucky/")) return "US";
  return TZ_COUNTRY[timeZone] || null;
}

/** Langue d'un pays ; le navigateur départage un pays bilingue (même règle que l'API). */
export function langForCountry(country, languages, countries, instanceLang = null) {
  const candidates = (countries && countries[country]) || [];
  if (!candidates.length) return null;
  const fallback = candidates.includes(instanceLang) ? instanceLang : candidates[0];
  return browserLanguages(languages).find((lang) => candidates.includes(lang)) || fallback;
}

/**
 * Langue à afficher.
 * @param {{saved?: string|null, serverLang?: string|null, timeZone?: string|null,
 *          languages?: string[], instanceLang?: string|null, countries?: Record<string, string[]>}} signals
 */
export function pickLanguage({
  saved = null,
  serverLang = null,
  timeZone = null,
  languages = [],
  instanceLang = null,
  countries = {},
} = {}) {
  if (saved && SUPPORTED.includes(saved)) return saved;
  if (serverLang && SUPPORTED.includes(serverLang)) return serverLang;
  const byCountry = langForCountry(countryFromTimeZone(timeZone), languages, countries, instanceLang);
  if (byCountry) return byCountry;
  const fromBrowser = matchLanguage(languages);
  if (fromBrowser) return fromBrowser;
  if (instanceLang && SUPPORTED.includes(instanceLang)) return instanceLang;
  return FALLBACK;
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
