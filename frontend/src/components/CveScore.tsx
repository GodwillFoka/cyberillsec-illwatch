// Lecture d'un score de CVE : composite décomposé (ADR-001), CVSS, EPSS.
import type { CveDetail } from "../api/types";

export const formatScore = (value: number | null | undefined) =>
  value === null || value === undefined ? "—" : value.toFixed(1).replace(".", ",");

/** EPSS (probabilité 0–1) en pourcentage français : 0,973 → « 97,3 % ». */
export const formatEpss = (value: number | null | undefined) =>
  value === null || value === undefined ? "—" : `${(value * 100).toFixed(1).replace(".", ",")} %`;

export function Breakdown({ cve }: { cve: CveDetail }) {
  const parts: [string, number][] = [
    ["Gravité (CVSS)", cve.breakdown.cvss],
    ["Probabilité d'exploitation (EPSS)", cve.breakdown.epss],
    ["Exploitation avérée (KEV)", cve.breakdown.kev],
    ["Exploit public", cve.breakdown.exploit],
    ["Campagnes de rançongiciel", cve.breakdown.ransomware],
  ];
  return (
    <dl className="facts">
      {parts.map(([label, value]) => (
        <div key={label} style={{ display: "contents" }}>
          <dt>{label}</dt>
          <dd className="mono">+{formatScore(value)}</dd>
        </div>
      ))}
      <dt>Score composite</dt>
      <dd className="mono">
        <strong>{formatScore(cve.breakdown.total)}</strong> / 100
        {cve.breakdown.kev_floor ? " · relevé en P1 (plancher KEV)" : ""}
      </dd>
    </dl>
  );
}
