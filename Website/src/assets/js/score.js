// Score de risque composite : copie fidèle de illwatch/modules/cve_tracker/scoring.py
// (ADR-001, plancher KEV de l'ADR-014). La parité est vérifiée des deux côtés sur le même jeu
// de cas : tests/score-vectors.json (node --test) et tests/test_site_score_parity.py (pytest).
//
//   R = min(100, CVSS × 3 + EPSS × 25 + KEV × 25 + exploit public × 10 + rançongiciel × 10)
//   P0 ≥ 80 · P1 ≥ 60 · P2 ≥ 40 · P3 sinon ; une CVE du catalogue KEV est au moins P1.

export const WEIGHTS = { cvss: 3, epss: 25, kev: 25, exploit: 10, ransomware: 10 };
export const THRESHOLDS = { P0: 80, P1: 60, P2: 40 };
export const SLA_HOURS = { P0: 24, P1: 24 * 7, P2: 24 * 30, P3: 24 * 90 };

const round2 = (value) => Math.round(value * 100) / 100;

export function classify(score) {
  if (score >= THRESHOLDS.P0) return "P0";
  if (score >= THRESHOLDS.P1) return "P1";
  if (score >= THRESHOLDS.P2) return "P2";
  return "P3";
}

/**
 * @param {{cvss?: number, epss?: number, kev?: boolean, exploit?: boolean, ransomware?: boolean}} input
 *        epss est une probabilité dans [0, 1].
 */
export function computeRisk({ cvss = 0, epss = 0, kev = false, exploit = false, ransomware = false } = {}) {
  if (!(cvss >= 0 && cvss <= 10)) throw new RangeError(`CVSS hors domaine [0, 10] : ${cvss}`);
  if (!(epss >= 0 && epss <= 1)) throw new RangeError(`EPSS hors domaine [0, 1] : ${epss}`);
  const parts = {
    cvss: round2(cvss * WEIGHTS.cvss),
    epss: round2(epss * WEIGHTS.epss),
    kev: kev ? WEIGHTS.kev : 0,
    exploit: exploit ? WEIGHTS.exploit : 0,
    ransomware: ransomware ? WEIGHTS.ransomware : 0,
  };
  const raw = cvss * WEIGHTS.cvss + epss * WEIGHTS.epss + parts.kev + parts.exploit + parts.ransomware;
  const total = round2(Math.min(100, raw));
  const byScore = classify(total);
  const kevFloor = kev && (byScore === "P2" || byScore === "P3");
  const priority = kevFloor ? "P1" : byScore;
  return { parts, total, priority, kevFloor, slaHours: SLA_HOURS[priority] };
}
