import assert from "node:assert/strict";
import { test } from "node:test";

import { evaluate } from "./audit-dev.mjs";

const advisory = (severity, ghsa) => ({
  source: 1,
  name: "picomatch",
  title: "ReDoS",
  severity,
  url: `https://github.com/advisories/${ghsa}`,
});

const report = {
  vulnerabilities: {
    picomatch: { severity: "high", via: [advisory("high", "GHSA-fc5q-39xc-vjpf")] },
    vite: { severity: "high", via: ["picomatch", "fdir"] },
  },
};
const exceptions = { "GHSA-fc5q-39xc-vjpf": { jusqu_au: "2026-12-15" } };

test("une alerte couverte par une exception en cours ne bloque pas", () => {
  const r = evaluate(report, exceptions, "2026-11-17");
  assert.equal(r.blocking.length, 0);
  assert.equal(r.accepted.length, 1);
});

test("une exception expirée bloque de nouveau", () => {
  const r = evaluate(report, exceptions, "2026-12-16");
  assert.equal(r.blocking.length, 1);
  assert.deepEqual(r.expired, ["GHSA-fc5q-39xc-vjpf"]);
});

test("une alerte élevée sans exception bloque, une alerte modérée non", () => {
  const other = {
    vulnerabilities: {
      a: { severity: "critical", via: [advisory("critical", "GHSA-aaaa-bbbb-cccc")] },
      b: { severity: "moderate", via: [advisory("moderate", "GHSA-dddd-eeee-ffff")] },
    },
  };
  const r = evaluate(other, exceptions, "2026-11-17");
  assert.deepEqual(
    r.blocking.map((x) => x.id),
    ["GHSA-aaaa-bbbb-cccc"],
  );
  assert.deepEqual(r.unused, ["GHSA-fc5q-39xc-vjpf"]);
});
