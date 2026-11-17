// Audit npm des outils de développement, avec exceptions datées (OPERATIONS § 14.7).
//
// `npm audit` ne sait pas ignorer une alerte précise. Ce script lit son rapport JSON, écarte
// les alertes listées dans `audit-exceptions.json` jusqu'à leur date limite, et échoue sur
// tout le reste : une alerte élevée ou critique sans exception, ou une exception expirée.
// Les dépendances livrées au navigateur restent auditées sans exception (étape séparée).
//
// Usage (depuis frontend/) : node scripts/audit-dev.mjs

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const BLOCKING = new Set(["high", "critical"]);

/** Identifiant GHSA d'une alerte npm, tiré de son URL. */
export function advisoryId(advisory) {
  const match = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i.exec(advisory.url || "");
  return match ? match[0] : String(advisory.source ?? advisory.title);
}

/**
 * Classe les alertes élevées ou critiques d'un rapport `npm audit --json`.
 * @returns {{blocking: object[], accepted: object[], expired: string[], unused: string[]}}
 */
export function evaluate(report, exceptions, today) {
  const seen = new Map();
  for (const vuln of Object.values(report.vulnerabilities || {})) {
    for (const via of vuln.via || []) {
      if (typeof via === "string" || !BLOCKING.has(via.severity)) continue;
      seen.set(advisoryId(via), via);
    }
  }
  const blocking = [];
  const accepted = [];
  const expired = new Set();
  for (const [id, advisory] of seen) {
    const exception = exceptions[id];
    if (exception && today <= exception.jusqu_au) accepted.push({ id, advisory, exception });
    else {
      if (exception) expired.add(id);
      blocking.push({ id, advisory });
    }
  }
  const unused = Object.keys(exceptions).filter((id) => !seen.has(id));
  return { blocking, accepted, expired: [...expired], unused };
}

function main() {
  const here = fileURLToPath(new URL("..", import.meta.url));
  const exceptions = JSON.parse(readFileSync(`${here}audit-exceptions.json`, "utf8"));
  let raw;
  try {
    raw = execFileSync("npm", ["audit", "--json"], { cwd: here, encoding: "utf8" });
  } catch (error) {
    raw = error.stdout; // npm audit sort en erreur dès qu'il trouve une alerte
  }
  const today = new Date().toISOString().slice(0, 10);
  const { blocking, accepted, expired, unused } = evaluate(JSON.parse(raw), exceptions, today);
  const gh = Boolean(process.env.GITHUB_ACTIONS);

  for (const { id, advisory, exception } of accepted) {
    const text = `${advisory.name} ${id} acceptée jusqu'au ${exception.jusqu_au} : ${advisory.title}`;
    console.log(gh ? `::warning title=npm audit (exception)::${text}` : `⚠ ${text}`);
  }
  for (const id of unused) {
    const text = `exception ${id} devenue inutile : la retirer de audit-exceptions.json`;
    console.log(gh ? `::warning title=npm audit (exception)::${text}` : `⚠ ${text}`);
  }
  for (const { id, advisory } of blocking) {
    const why = expired.includes(id) ? "exception expirée, à revoir" : "sans exception";
    const text = `${advisory.name} ${advisory.severity} ${id} (${why}) : ${advisory.title} ${advisory.url || ""}`;
    console.log(gh ? `::error title=npm audit (dév.)::${text}` : `✘ ${text}`);
  }
  if (blocking.length > 0) process.exit(1);
  console.log(`✔ audit des outils de développement : aucune alerte élevée sans exception (${accepted.length} acceptée(s))`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
