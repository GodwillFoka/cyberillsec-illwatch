// Langue de l'interface à l'ouverture (ADR-027) — même ordre que le site et l'API :
//   1. choix fait par l'utilisateur (mémorisé dans ce navigateur) ;
//   2. réponse de `GET /api/v1/locale` : pays de l'adresse IP (ou de l'instance sur un réseau
//      interne), le navigateur départageant les pays bilingues ; puis navigateur ; puis langue
//      de l'instance ; puis anglais ;
//   3. API injoignable : langue du navigateur, puis anglais.
import { isLang, type Lang } from "./core.js";

export const STORAGE_KEY = "illwatch.lang";
export const LOCALE_ENDPOINT = "/api/v1/locale";
const TIMEOUT_MS = 1500;

/** Première langue prise en charge d'une liste d'étiquettes BCP 47 (« de-AT » → « de »). */
export function matchLanguage(tags: readonly (string | null | undefined)[]): Lang | null {
  for (const tag of tags) {
    if (typeof tag !== "string") continue;
    const primary = tag.trim().toLowerCase().split(/[-_]/)[0];
    if (isLang(primary)) return primary;
  }
  return null;
}

export interface Signals {
  saved?: string | null;
  server?: string | null;
  languages?: readonly (string | null | undefined)[];
}

export function pickLanguage({ saved = null, server = null, languages = [] }: Signals = {}): Lang {
  if (isLang(saved)) return saved;
  if (isLang(server)) return server;
  return matchLanguage(languages) ?? "en";
}

interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export function readSaved(storage: StorageLike | null): string | null {
  try {
    return storage ? storage.getItem(STORAGE_KEY) : null;
  } catch {
    return null; // stockage refusé : aucune préférence
  }
}

export function saveChoice(storage: StorageLike | null, lang: Lang): void {
  try {
    storage?.setItem(STORAGE_KEY, lang);
  } catch {
    // stockage refusé : le choix vaut pour cet onglet seulement
  }
}

/** Langue décidée par le serveur, ou null s'il ne répond pas dans le délai. */
export async function fetchServerLanguage(
  fetcher: typeof fetch = fetch,
  timeoutMs = TIMEOUT_MS,
): Promise<Lang | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetcher(LOCALE_ENDPOINT, {
      signal: controller.signal,
      credentials: "omit", // la réponse porte déjà « Cache-Control: no-store »
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return null;
    const body: unknown = await response.json();
    const lang = body && typeof body === "object" ? (body as { lang?: unknown }).lang : null;
    return isLang(lang) ? lang : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
