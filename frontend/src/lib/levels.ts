// Échelle de priorité unique P0–P3 (docs/DESIGN_SYSTEM.md, brand book ILLWATCH v2), appliquée aux sévérités et priorités.
// Libellés traduits à la lecture (ADR-027) : voir labels.i18n.ts.
import { labelTable, labels } from "./labels.i18n.js";

export type Tone = "p0" | "p1" | "p2" | "p3";

const TONES: Record<string, Tone> = {
  CRITICAL: "p0",
  HIGH: "p1",
  MEDIUM: "p2",
  LOW: "p3",
  P0_CRITIQUE: "p0",
  P1_ELEVE: "p1",
  P2_MOYEN: "p2",
  P3_FAIBLE: "p3",
};

const SEVERITY_LABEL = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
const PRIORITY_LABEL: Record<string, string> = {
  P0_CRITIQUE: "P0",
  P1_ELEVE: "P1",
  P2_MOYEN: "P2",
  P3_FAIBLE: "P3",
};

/** Marque pleine de chaque niveau (graphiques, barres) : jetons --p0-mark à --p3-mark. */
export const TONE_COLORS: Record<Tone, string> = {
  p0: "#E5484D",
  p1: "#F2B33D",
  p2: "#5B9BF5",
  p3: "#6E7A93",
};

/** Couleurs du thème des graphiques (jetons ILLWATCH v2, thème Nuit). Les courbes et barres
 * sans gravité sont en Signal, la couleur de la veille. */
export const CHART = {
  text: "#A3ACBF",
  strong: "#ECEFF5",
  line: "#222C42",
  grid: "#1A2336",
  panel: "#0F1626",
  accent: "#22D3EE",
  font: "Inter, system-ui, sans-serif",
};

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export const PRIORITY_ORDER = ["P0_CRITIQUE", "P1_ELEVE", "P2_MOYEN", "P3_FAIBLE"];

export function toneOf(level: string): Tone {
  return TONES[level] ?? "p3";
}

export function levelLabel(level: string): string {
  if (SEVERITY_LABEL.has(level)) return labels(`level.${level}` as Parameters<typeof labels>[0]);
  return PRIORITY_LABEL[level] ?? level;
}

export function rankOf(level: string): number {
  return Number(toneOf(level).slice(1));
}

const STATUSES = ["NOUVEAU", "ANALYSE", "CONFINEMENT", "ERADICATION", "RECUPERATION", "CLOTURE"];

export const INCIDENT_STATUS = labelTable("status", STATUSES);

export const ALERT_REASON = labelTable("reason", ["kev", "epss", "nvd"]);

/** Niveaux SOC (M9, ADR-022) : l'escalade ne fait que monter. */
export const SOC_TIERS = ["L1", "L2", "L3"];
export const TIER_LABEL = labelTable("tier", SOC_TIERS);

/** Rôles des comptes (barre supérieure, administration). */
export const ROLE_LABEL = labelTable("role", ["ADMIN", "ANALYST", "VIEWER"]);

/** Phases NIST où s'inscrit une recommandation de réponse. */
export const PHASE_LABEL = labelTable("phase", STATUSES);
