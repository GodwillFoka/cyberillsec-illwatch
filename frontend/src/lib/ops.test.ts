import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { auditLabel, formatBytes, formatDuration, formatMs, generatePassword, successRate } from "./ops.js";

describe("durées et tailles", () => {
  it("durées lisibles", () => {
    assert.equal(formatDuration(45), "45 s");
    assert.equal(formatDuration(900), "15 min");
    assert.equal(formatDuration(3600), "1 h");
    assert.equal(formatDuration(5400), "1 h 30 min");
    assert.equal(formatDuration(86_400), "1 j");
    assert.equal(formatDuration(90_000), "1 j 1 h");
    assert.equal(formatDuration(-1), "—");
  });

  it("millisecondes et octets", () => {
    assert.equal(formatMs(840), "840 ms");
    assert.equal(formatMs(12_400), "12,4 s");
    assert.equal(formatBytes(20 * 1024 * 1024), "20 Mio");
    assert.equal(formatBytes(1536), "1,5 Kio");
  });

  it("taux de réussite", () => {
    assert.equal(successRate(0, 0), null);
    assert.equal(successRate(28, 0), 100);
    assert.equal(successRate(28, 7), 75);
  });
});

describe("mot de passe généré", () => {
  it("longueur, alphabet sans ambiguïté, tirages distincts", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      const password = generatePassword();
      assert.equal(password.length, 20);
      assert.match(password, /^[A-HJ-NP-Za-km-z2-9_-]+$/);
      seen.add(password);
    }
    assert.equal(seen.size, 200);
    assert.equal(generatePassword(32).length, 32);
  });
});

describe("journal d'audit", () => {
  it("libellé français, action brute si inconnue", () => {
    assert.equal(auditLabel("user.disable"), "Compte désactivé");
    assert.equal(auditLabel("autre.chose"), "autre.chose");
  });
});
