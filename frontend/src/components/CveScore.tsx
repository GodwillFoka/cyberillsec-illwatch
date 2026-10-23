// Lecture d'un score de CVE : composite décomposé (ADR-001), CVSS, EPSS.
import type { CveDetail } from "../api/types";
import { currentLocale } from "../i18n/core";
import { formatDecimal } from "../lib/format";
import { labels } from "../lib/labels.i18n";
import { ui } from "./components.i18n";

/** Score à une décimale fixe, séparateur de la langue : « 62,2 », « 62.2 ». */
export const formatScore = (value: number | null | undefined) =>
  value === null || value === undefined
    ? "—"
    : new Intl.NumberFormat(currentLocale(), {
        minimumFractionDigits: 1,
        maximumFractionDigits: 1,
      }).format(value);

/** EPSS (probabilité 0–1) en pourcentage : 0,973 → « 97,3 % » (« 97.3% » en anglais). */
export const formatEpss = (value: number | null | undefined) =>
  value === null || value === undefined ? "—" : labels("unit.percent", { n: formatDecimal(value * 100) });

export function Breakdown({ cve }: { cve: CveDetail }) {
  const parts: [string, number][] = [
    [ui("partCvss"), cve.breakdown.cvss],
    [ui("partEpss"), cve.breakdown.epss],
    [ui("partKev"), cve.breakdown.kev],
    [ui("partExploit"), cve.breakdown.exploit],
    [ui("partRansomware"), cve.breakdown.ransomware],
  ];
  return (
    <dl className="facts">
      {parts.map(([label, value]) => (
        <div key={label} style={{ display: "contents" }}>
          <dt>{label}</dt>
          <dd className="mono">+{formatScore(value)}</dd>
        </div>
      ))}
      <dt>{ui("composite")}</dt>
      <dd className="mono">
        <strong>{formatScore(cve.breakdown.total)}</strong> / 100
        {cve.breakdown.kev_floor ? ui("kevFloor") : ""}
      </dd>
    </dl>
  );
}
