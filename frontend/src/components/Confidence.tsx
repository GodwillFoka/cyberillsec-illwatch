// Confiance d'un IOC (ADR-017) : jauge en Signal, la couleur de la veille, jamais aux couleurs de gravité —
// la confiance dit « peut-on agir ? », la gravité dit « à quel point ce serait grave ».

import { labelTable } from "../lib/labels.i18n";
import { ui } from "./components.i18n";

export const CONFIDENCE_LABEL = labelTable("confidence", ["ELEVEE", "MOYENNE", "FAIBLE"]);

export function ConfidenceMeter({ value, level }: { value: number; level: string }) {
  const steps = 5;
  const filled = Math.round((Math.max(0, Math.min(100, value)) / 100) * steps);
  return (
    <span className={`confidence ${level.toLowerCase()}`} title={ui("confidenceTitle", { level: CONFIDENCE_LABEL[level] ?? level, value: String(value) })}>
      <span className="pips" aria-hidden="true">
        {Array.from({ length: steps }, (_, i) => (
          <span key={i} className={i < filled ? "pip on" : "pip"} />
        ))}
      </span>
      <span className="mono">{value}</span>
      <span className="sr-only">{ui("confidenceSr", { level: CONFIDENCE_LABEL[level] ?? level })}</span>
    </span>
  );
}

const RELIABILITY_LABEL = labelTable("reliability", ["A", "B", "C", "D", "E", "F"]);

/** Échelle de fiabilité de l'Amirauté : [code, libellé dans la langue courante]. */
export function reliabilityScale(): [string, string][] {
  return ["A", "B", "C", "D", "E", "F"].map((code) => [code, RELIABILITY_LABEL[code]]);
}
