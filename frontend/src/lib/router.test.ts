import { describe, expect, it } from "vitest";

import { isActive, isInternalPath } from "./router";

describe("routage", () => {
  it("n'accepte que les adresses internes", () => {
    expect(isInternalPath("/")).toBe(true);
    expect(isInternalPath("/incidents/42?onglet=chronologie")).toBe(true);
    for (const hostile of ["//evil.example", "/\\evil.example", "https://evil.example", "javascript:alert(1)", "incidents", "/a b"]) {
      expect(isInternalPath(hostile)).toBe(false);
    }
  });

  it("repère l'écran actif", () => {
    expect(isActive("/", "/")).toBe(true);
    expect(isActive("/triage", "/")).toBe(false);
    expect(isActive("/incidents/42", "/incidents")).toBe(true);
    expect(isActive("/incidentsx", "/incidents")).toBe(false);
  });
});
