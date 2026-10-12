// Confiance d'un IOC (ADR-017) : jauge en Signal, la couleur de la veille, jamais aux couleurs de gravité —
// la confiance dit « peut-on agir ? », la gravité dit « à quel point ce serait grave ».

export const CONFIDENCE_LABEL: Record<string, string> = {
  ELEVEE: "Élevée",
  MOYENNE: "Moyenne",
  FAIBLE: "Faible",
};

export function ConfidenceMeter({ value, level }: { value: number; level: string }) {
  const steps = 5;
  const filled = Math.round((Math.max(0, Math.min(100, value)) / 100) * steps);
  return (
    <span className={`confidence ${level.toLowerCase()}`} title={`Confiance ${CONFIDENCE_LABEL[level] ?? level} : ${value}/100`}>
      <span className="pips" aria-hidden="true">
        {Array.from({ length: steps }, (_, i) => (
          <span key={i} className={i < filled ? "pip on" : "pip"} />
        ))}
      </span>
      <span className="mono">{value}</span>
      <span className="sr-only">sur 100, {CONFIDENCE_LABEL[level] ?? level}</span>
    </span>
  );
}

export const RELIABILITY: [string, string][] = [
  ["A", "A : totalement fiable"],
  ["B", "B : habituellement fiable"],
  ["C", "C : assez fiable"],
  ["D", "D : pas toujours fiable"],
  ["E", "E : peu fiable"],
  ["F", "F : fiabilité inconnue"],
];
