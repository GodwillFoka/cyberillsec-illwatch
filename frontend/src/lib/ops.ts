// Règles d'affichage des écrans Sources CTI et Administration (sans JSX : testées par Node).

/** Durée lisible : 45 → « 45 s », 900 → « 15 min », 3600 → « 1 h », 90000 → « 1 j 1 h ». */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  if (hours < 24) return rest ? `${hours} h ${rest} min` : `${hours} h`;
  const days = Math.floor(hours / 24);
  const h = hours % 24;
  return h ? `${days} j ${h} h` : `${days} j`;
}

/** Millisecondes : 840 → « 840 ms », 12_400 → « 12,4 s ». */
export function formatMs(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1).replace(".", ",")} s`;
}

/** Octets en unités binaires françaises : 20_971_520 → « 20 Mio ». */
export function formatBytes(bytes: number): string {
  const units = ["o", "Kio", "Mio", "Gio"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const text = Number.isInteger(value) ? String(value) : value.toFixed(1).replace(".", ",");
  return `${text} ${units[unit]}`;
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

/** Libellés français des actions du journal d'audit (le résultat SUCCESS / FAILURE / DENIED
 * est affiché à part) ; l'action brute sinon. */
const AUDIT_LABELS: Record<string, string> = {
  "auth.login": "Connexion",
  "auth.logout": "Déconnexion",
  "auth.refresh": "Renouvellement de session",
  "authz.denied": "Accès refusé (rôle)",
  "user.create": "Compte créé",
  "user.role": "Rôle modifié",
  "user.disable": "Compte désactivé",
  "user.enable": "Compte réactivé",
  "user.password_reset": "Mot de passe réinitialisé",
  "user.revoke_sessions": "Sessions révoquées",
  "feed.create": "Source ajoutée",
  "feed.update": "Source modifiée",
  "feed.delete": "Source supprimée",
  "indicator.submit": "Indicateurs soumis",
  "alert.ack": "Alerte acquittée",
  "data.export": "Export de données",
  "hunt.run": "Chasse lancée",
  "enrichment.import": "Base d'enrichissement importée",
  "asset.create": "Actif déclaré",
  "asset.update": "Actif modifié",
  "asset.delete": "Actif supprimé",
  "asset.import": "Inventaire importé",
  "correlation.run": "Corrélation lancée",
  "correlation.ack": "Corrélation acquittée",
};

export function auditLabel(action: string): string {
  return AUDIT_LABELS[action] ?? action;
}
