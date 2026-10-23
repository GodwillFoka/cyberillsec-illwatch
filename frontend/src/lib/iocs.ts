// Règles de l'écran Indicateurs (sans JSX : testées directement par Node).
import { currentLocale } from "../i18n/core.js";
import { labels } from "./labels.i18n.js";

/** Taille maximale d'un lot accepté par `POST /indicators` (MAX_BATCH_SIZE côté serveur). */
export const MAX_BATCH = 1000;

/** Observables au plus par session de chasse (MAX_OBSERVABLES côté serveur). */
export const MAX_HUNT_OBSERVABLES = 10_000;

const IOC_TYPE_CODES = ["IPV4", "IPV6", "NETWORK", "DOMAIN", "URL", "HASH_SHA256", "HASH_SHA1", "HASH_MD5", "EMAIL"];
const FIXED_LABELS: Record<string, string> = {
  IPV4: "IPv4",
  IPV6: "IPv6",
  URL: "URL",
  HASH_SHA256: "SHA-256",
  HASH_SHA1: "SHA-1",
  HASH_MD5: "MD5",
};

export function iocTypeLabel(type: string): string {
  if (type in FIXED_LABELS) return FIXED_LABELS[type];
  if (type === "NETWORK" || type === "DOMAIN" || type === "EMAIL") return labels(`ioc.${type}`);
  return type;
}

/** Types d'IOC proposés dans les formulaires : [code, libellé dans la langue courante]. */
export function iocTypes(): [string, string][] {
  return IOC_TYPE_CODES.map((code) => [code, iocTypeLabel(code)]);
}

export interface Batch {
  /** Valeurs à soumettre, dans l'ordre, sans doublon exact. */
  values: string[];
  /** Doublons exacts retirés avant l'envoi. */
  duplicates: number;
  /** Valeurs au-delà du plafond, non envoyées. */
  overflow: number;
}

/**
 * Découpe un texte collé (bulletin, liste) en valeurs : une par ligne, ou séparées par des
 * espaces, tabulations, virgules ou points-virgules. Les lignes commençant par « # » sont des
 * commentaires. La validation et la normalisation (`evil[.]com`, `hxxp://`) restent au serveur,
 * qui renvoie la liste des rejets : rien n'est écarté ici en silence.
 */
export function splitBatch(text: string, max: number = MAX_BATCH): Batch {
  const seen = new Set<string>();
  const values: string[] = [];
  let duplicates = 0;
  for (const rawLine of text.split(/\r\n|\r|\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    for (const token of line.split(/[\s,;]+/)) {
      if (!token) continue;
      if (seen.has(token)) {
        duplicates += 1;
        continue;
      }
      seen.add(token);
      values.push(token);
    }
  }
  return {
    values: values.slice(0, max),
    duplicates,
    overflow: Math.max(0, values.length - max),
  };
}

/** Nom de fichier d'un en-tête `Content-Disposition` (forme simple `filename="…"`). */
export function filenameFrom(disposition: string | null, fallback: string): string {
  const match = /filename="([^"/\\]+)"/.exec(disposition ?? "");
  return match ? match[1] : fallback;
}

/** Liste d'actifs saisie (« FortiOS, Exchange ; Confluence ») : virgules, points-virgules ou lignes. */
export function splitAssets(text: string): string[] {
  const seen = new Set<string>();
  const assets: string[] = [];
  for (const raw of text.split(/[,;\r\n]+/)) {
    const asset = raw.trim();
    const key = asset.toLowerCase();
    if (!asset || seen.has(key)) continue;
    seen.add(key);
    assets.push(asset);
  }
  return assets;
}

const regionNames = new Map<string, Intl.DisplayNames>();

/** Nom d'un pays dans la langue courante, à partir de son code ISO 3166-1 alpha-2
 * (« US » → « États-Unis (US) »). */
export function countryName(code: string | null | undefined): string {
  if (!code) return labels("country.unknown");
  const locale = currentLocale();
  let regions = regionNames.get(locale);
  if (!regions) {
    regions = new Intl.DisplayNames([locale], { type: "region" });
    regionNames.set(locale, regions);
  }
  try {
    const name = regions.of(code.toUpperCase());
    return name && name !== code.toUpperCase() ? `${name} (${code.toUpperCase()})` : code.toUpperCase();
  } catch {
    return code;
  }
}
