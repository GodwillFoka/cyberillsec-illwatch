import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { isActive, isInternalPath } from "./paths.ts";

describe("routage", () => {
  it("n'accepte que les adresses internes", () => {
    assert.equal(isInternalPath("/"), true);
    assert.equal(isInternalPath("/incidents/42?onglet=chronologie"), true);
    const hostile = [
      "//evil.example",
      "/\\evil.example",
      "https://evil.example",
      "javascript:alert(1)",
      "incidents",
      "/a b",
    ];
    for (const address of hostile) assert.equal(isInternalPath(address), false, address);
  });

  it("repère l'écran actif", () => {
    assert.equal(isActive("/", "/"), true);
    assert.equal(isActive("/triage", "/"), false);
    assert.equal(isActive("/incidents/42", "/incidents"), true);
    assert.equal(isActive("/incidentsx", "/incidents"), false);
  });
});
