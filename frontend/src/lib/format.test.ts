import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { formatAge, formatAgo, formatDay, formatHours, formatNumber, formatShare, formatTime } from "./format.js";
import { rankOf, toneOf } from "./levels.js";

describe("formats", () => {
  it("formate les nombres à la française", () => {
    assert.equal(formatNumber(528453).replace(/\s/g, " "), "528 453");
    assert.equal(formatNumber(null), "-");
  });

  it("affiche l'heure en UTC", () => {
    const date = new Date("2026-10-10T07:05:09Z");
    assert.equal(formatTime(date, true), "07:05");
    assert.equal(formatTime(date, true, true), "07:05:09");
    assert.equal(formatDay(date, true), "10/10");
  });

  it("exprime une ancienneté", () => {
    const now = new Date("2026-10-10T12:00:00Z");
    assert.equal(formatAge(new Date("2026-10-10T11:59:30Z"), now), "à l'instant");
    assert.equal(formatAge(new Date("2026-10-10T11:56:00Z"), now), "4\u00a0min");
    assert.equal(formatAge(new Date("2026-10-10T09:00:00Z"), now), "3\u00a0h");
    assert.equal(formatAge(new Date("2026-10-07T12:00:00Z"), now), "3\u00a0j");
    assert.equal(formatAgo(new Date("2026-10-10T11:59:30Z"), now), "à l'instant");
    assert.equal(formatAgo(new Date("2026-10-10T11:56:00Z"), now), "il y a 4\u00a0min");
  });
});

describe("échelle de priorité", () => {
  it("ramène sévérités et priorités à P0-P3", () => {
    assert.equal(toneOf("CRITICAL"), "p0");
    assert.equal(toneOf("P1_ELEVE"), "p1");
    assert.equal(rankOf("MEDIUM"), 2);
    assert.equal(toneOf("INCONNU"), "p3");
  });

  it("exprime une durée et une part", () => {
    assert.equal(formatHours(null), "-");
    assert.equal(formatHours(0.25), "15\u00a0min");
    assert.equal(formatHours(3.46), "3,5\u00a0h");
    assert.equal(formatHours(50), "2,1\u00a0j");
    assert.equal(formatShare(0.834), "83\u00a0%");
    assert.equal(formatShare(undefined), "-");
  });
});
