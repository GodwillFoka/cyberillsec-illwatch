// Parité du simulateur avec le moteur (ADR-027, décision 6) : mêmes cas que
// tests/test_site_score_parity.py, côté Python.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { computeRisk } from "../src/assets/js/score.js";

const { cases } = JSON.parse(readFileSync(new URL("./score-vectors.json", import.meta.url), "utf8"));

for (const { name, input, expected } of cases) {
  test(`simulateur = moteur : ${name}`, () => {
    const result = computeRisk(input);
    assert.equal(result.total, expected.total);
    assert.equal(result.priority, expected.priority);
    assert.equal(result.kevFloor, expected.kevFloor);
  });
}

test("la décomposition additionne le score (hors bornage)", () => {
  const r = computeRisk({ cvss: 7.5, epss: 0.18, kev: true, exploit: true, ransomware: false });
  const sum = Object.values(r.parts).reduce((a, b) => a + b, 0);
  assert.equal(Math.round(sum * 100) / 100, r.total);
});

test("valeurs hors domaine refusées, comme le moteur", () => {
  assert.throws(() => computeRisk({ cvss: 10.1 }), RangeError);
  assert.throws(() => computeRisk({ epss: 1.5 }), RangeError);
  assert.throws(() => computeRisk({ cvss: Number.NaN }), RangeError);
});

test("délai de correction selon la priorité", () => {
  assert.equal(computeRisk({ cvss: 10, epss: 1, kev: true }).slaHours, 24);
  assert.equal(computeRisk({ kev: true }).slaHours, 24 * 7);
  assert.equal(computeRisk({}).slaHours, 24 * 90);
});
