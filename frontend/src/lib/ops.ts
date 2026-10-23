// Règles d'affichage des écrans Sources CTI et Administration (sans JSX : testées par Node).
// Unités et libellés dans la langue courante (ADR-027).
import { formatDecimal } from "./format.js";
import { labels } from "./labels.i18n.js";

/** Durée lisible : 45 → « 45 s », 900 → « 15 min », 3600 → « 1 h », 90000 → « 1 j 1 h ». */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return labels("unit.s", { n: Math.round(seconds) });
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return labels("unit.min_plain", { n: minutes });
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  if (hours < 24) return rest ? labels("unit.h_min", { h: hours, m: rest }) : labels("unit.h_plain", { n: hours });
  const days = Math.floor(hours / 24);
  const h = hours % 24;
  return h ? labels("unit.d_h", { d: days, h }) : labels("unit.d_plain", { n: days });
}

/** Millisecondes : 840 → « 840 ms », 12_400 → « 12,4 s ». */
export function formatMs(ms: number): string {
  if (ms < 1000) return labels("unit.ms", { n: ms });
  return labels("unit.s", { n: formatDecimal(ms / 1000) });
}

/** Octets en unités binaires : 20_971_520 → « 20 Mio » (« 20 MiB » en anglais). */
export function formatBytes(bytes: number): string {
  const units = ["unit.bytes", "unit.kib", "unit.mib", "unit.gib"] as const;
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const text = Number.isInteger(value) ? String(value) : formatDecimal(value);
  return `${text} ${labels(units[unit])}`;
}

/** Taux de réussite des collectes, en pourcentage entier ; `null` sans collecte. */
export function successRate(runs: number, errors: number): number | null {
  if (runs <= 0) return null;
  return Math.round(((runs - errors) / runs) * 100);
}

/** Intervalles de collecte proposés (secondes), du plus fréquent au plus espacé. */
export const POLLING_CHOICES = [900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 24 * 3600];

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_";

/**
 * Mot de passe aléatoire (générateur cryptographique du navigateur), sans caractères
 * ambigus (0/O, 1/l/I). 20 caractères ≈ 117 bits : au-delà de la politique (12 minimum).
 */
export function generatePassword(length = 20): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  // Rejet des octets au-delà du plus grand multiple de l'alphabet : tirage sans biais.
  const limit = 256 - (256 % ALPHABET.length);
  let out = "";
  let i = 0;
  while (out.length < length) {
    if (i >= bytes.length) {
      crypto.getRandomValues(bytes);
      i = 0;
    }
    const b = bytes[i++];
    if (b < limit) out += ALPHABET[b % ALPHABET.length];
  }
  return out;
}

/** Libellés des actions du journal d'audit (le résultat SUCCESS / FAILURE / DENIED est
 * affiché à part) ; l'action brute sinon. */
const AUDIT_ACTIONS = new Set([
  "auth.login",
  "auth.logout",
  "auth.refresh",
  "authz.denied",
  "user.create",
  "user.role",
  "user.disable",
  "user.enable",
  "user.password_reset",
  "user.revoke_sessions",
  "feed.create",
  "feed.update",
  "feed.delete",
  "indicator.submit",
  "alert.ack",
  "data.export",
  "hunt.run",
  "enrichment.import",
  "asset.create",
  "asset.update",
  "asset.delete",
  "asset.import",
  "correlation.run",
  "correlation.ack",
]);

export function auditLabel(action: string): string {
  return AUDIT_ACTIONS.has(action) ? labels(`audit.${action}` as Parameters<typeof labels>[0]) : action;
}
