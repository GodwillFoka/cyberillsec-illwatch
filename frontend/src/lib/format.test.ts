import { describe, expect, it } from "vitest";

import { formatAge, formatDay, formatNumber, formatTime } from "./format";
import { rankOf, toneOf } from "./levels";

describe("formats", () => {
  it("formate les nombres à la française", () => {
    expect(formatNumber(528453).replace(/\s/g, " ")).toBe("528 453");
    expect(formatNumber(null)).toBe("—");
  });

  it("affiche l'heure en UTC", () => {
    const date = new Date("2026-10-10T07:05:09Z");
    expect(formatTime(date, true)).toBe("07:05");
    expect(formatTime(date, true, true)).toBe("07:05:09");
    expect(formatDay(date, true)).toBe("10/10");
  });

  it("exprime une ancienneté", () => {
    const now = new Date("2026-10-10T12:00:00Z");
    expect(formatAge(new Date("2026-10-10T11:59:30Z"), now)).toBe("à l'instant");
    expect(formatAge(new Date("2026-10-10T11:56:00Z"), now)).toBe("4 min");
    expect(formatAge(new Date("2026-10-10T09:00:00Z"), now)).toBe("3 h");
    expect(formatAge(new Date("2026-10-07T12:00:00Z"), now)).toBe("3 j");
  });
});

describe("échelle de priorité", () => {
  it("ramène sévérités et priorités à P0–P3", () => {
    expect(toneOf("CRITICAL")).toBe("p0");
    expect(toneOf("P1_ELEVE")).toBe("p1");
    expect(rankOf("MEDIUM")).toBe(2);
    expect(toneOf("INCONNU")).toBe("p3");
  });
});
