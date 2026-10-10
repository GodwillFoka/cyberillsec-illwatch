// Règles de l'écran Indicateurs (sans JSX : testées directement par Node).

/** Taille maximale d'un lot accepté par `POST /indicators` (MAX_BATCH_SIZE côté serveur). */
export const MAX_BATCH = 1000;

export const IOC_TYPES: [string, string][] = [
  ["IPV4", "IPv4"],
  ["IPV6", "IPv6"],
  ["DOMAIN", "Domaine"],
  ["URL", "URL"],
  ["HASH_SHA256", "SHA-256"],
  ["HASH_SHA1", "SHA-1"],
  ["HASH_MD5", "MD5"],
  ["EMAIL", "E-mail"],
];

const TYPE_LABELS = new Map(IOC_TYPES);

export function iocTypeLabel(type: string): string {
  return TYPE_LABELS.get(type) ?? type;
}

export interface Batch {
  /** Valeurs à soumettre, dans l'ordre, sans doublon exact. */
  values: string[];
  /** Doublons exacts retirés avant l'envoi. */
  duplicates: number;
  /** Valeurs au-delà de MAX_BATCH, non envoyées. */
  overflow: number;
}

/**
 * Découpe un texte collé (bulletin, liste) en valeurs : une par ligne, ou séparées par des
 * espaces, tabulations, virgules ou points-virgules. Les lignes commençant par « # » sont des
 * commentaires. La validation et la normalisation (`evil[.]com`, `hxxp://`) restent au serveur,
 * qui renvoie la liste des rejets : rien n'est écarté ici en silence.
 */
export function splitBatch(text: string): Batch {
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
    values: values.slice(0, MAX_BATCH),
    duplicates,
    overflow: Math.max(0, values.length - MAX_BATCH),
  };
}

/** Nom de fichier d'un en-tête `Content-Disposition` (forme simple `filename="…"`). */
export function filenameFrom(disposition: string | null, fallback: string): string {
  const match = /filename="([^"/\\]+)"/.exec(disposition ?? "");
  return match ? match[1] : fallback;
}
