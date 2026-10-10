import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MAX_BATCH, filenameFrom, iocTypeLabel, splitBatch } from "./iocs.js";

describe("lot d'IOC collé", () => {
  it("découpe par ligne et par séparateur, ignore commentaires et doublons", () => {
    const batch = splitBatch(
      "# bulletin CERT-FR\r\n198.51.100.7\n\nevil[.]example.com, hxxp://x.example/a ; 198.51.100.7\n\t44d88612fea8a8f36de82e1278abb02f  \n",
    );
    assert.deepEqual(batch.values, [
      "198.51.100.7",
      "evil[.]example.com",
      "hxxp://x.example/a",
      "44d88612fea8a8f36de82e1278abb02f",
    ]);
    assert.equal(batch.duplicates, 1);
    assert.equal(batch.overflow, 0);
  });

  it("plafonne au maximum du serveur et compte le reste", () => {
    const text = Array.from({ length: MAX_BATCH + 5 }, (_, i) => `host${i}.example`).join("\n");
    const batch = splitBatch(text);
    assert.equal(batch.values.length, MAX_BATCH);
    assert.equal(batch.overflow, 5);
  });

  it("texte vide : rien à envoyer", () => {
    assert.deepEqual(splitBatch("  \n# rien\n"), { values: [], duplicates: 0, overflow: 0 });
  });
});

describe("affichage", () => {
  it("libellés de type, valeur brute si inconnue", () => {
    assert.equal(iocTypeLabel("HASH_SHA256"), "SHA-256");
    assert.equal(iocTypeLabel("ASN"), "ASN");
  });

  it("nom de fichier d'export, jamais un chemin", () => {
    assert.equal(
      filenameFrom('attachment; filename="illwatch-iocs-20261010T150000Z.csv"', "x.csv"),
      "illwatch-iocs-20261010T150000Z.csv",
    );
    assert.equal(filenameFrom('attachment; filename="../../etc/passwd"', "x.csv"), "x.csv");
    assert.equal(filenameFrom(null, "x.csv"), "x.csv");
  });
});
