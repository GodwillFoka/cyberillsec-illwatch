import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { asUuid, isActive, isInternalPath } from "./paths.js";

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

describe("identifiants lus dans l'adresse", () => {
  it("n'accepte qu'un UUID, rien qui puisse remonter dans l'API", () => {
    assert.equal(asUuid("1B4E28BA-2FA1-11D2-883F-0016D3CCA427"), "1b4e28ba-2fa1-11d2-883f-0016d3cca427");
    for (const hostile of ["../dashboard/export?dataset=iocs", "1b4e28ba-2fa1-11d2-883f-0016d3cca427/..", "", null]) {
      assert.equal(asUuid(hostile), null, String(hostile));
    }
  });
});
