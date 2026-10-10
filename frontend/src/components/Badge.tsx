import { levelLabel, toneOf } from "../lib/levels";

/** Badge de l'échelle P0–P3 pour une sévérité ou une priorité. */
export function LevelBadge({ level }: { level: string }) {
  return <span className={`badge ${toneOf(level)}`}>{levelLabel(level)}</span>;
}
