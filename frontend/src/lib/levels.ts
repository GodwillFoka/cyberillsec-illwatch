// Échelle de priorité unique P0–P3 (docs/DESIGN_SYSTEM.md, brand book ILL Watch v2), appliquée aux sévérités et priorités.

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

const LABELS: Record<string, string> = {
  CRITICAL: "Critique",
  HIGH: "Élevée",
  MEDIUM: "Moyenne",
  LOW: "Faible",
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

/** Couleurs du thème des graphiques (jetons ILL Watch v2, thème Nuit). Les courbes et barres
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
  return LABELS[level] ?? level;
}

export function rankOf(level: string): number {
  return Number(toneOf(level).slice(1));
}

export const INCIDENT_STATUS: Record<string, string> = {
  NOUVEAU: "Nouveau",
  ANALYSE: "En analyse",
  CONFINEMENT: "Confinement",
  ERADICATION: "Éradication",
  RECUPERATION: "Récupération",
  CLOTURE: "Clôturé",
};

export const ALERT_REASON: Record<string, string> = {
  kev: "Catalogue KEV",
  epss: "Hausse EPSS",
  nvd: "Mise à jour NVD",
};
