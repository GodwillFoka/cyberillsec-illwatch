// Tests du lanceur intégré de Node : `npm test` les compile avec tsc (tsconfig.test.json)
// puis les exécute ; « ./sse.js » désigne sse.ts (convention ESM de TypeScript).
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { SseParser, queriesFor, toLiveEvent } from "./sse.js";

describe("SseParser", () => {
  it("assemble un message reçu en plusieurs morceaux", () => {
    const parser = new SseParser();
    assert.deepEqual(parser.push("retry: 5000\n: illwatch\n\nid: a1\nevent: alert.cr").messages, []);
    const feed = parser.push('eated\ndata: {"kind":"alert.created"}\n\n');
    assert.deepEqual(feed.messages, [
      { id: "a1", event: "alert.created", data: '{"kind":"alert.created"}' },
    ]);
  });

  it("lit le délai de reconnexion et ignore les battements", () => {
    const parser = new SseParser();
    const feed = parser.push("retry: 5000\n\n: ping\n\n");
    assert.equal(feed.retryMs, 5000);
    assert.deepEqual(feed.messages, []);
  });

  it("accepte les fins de ligne CRLF et les données sur plusieurs lignes", () => {
    const parser = new SseParser();
    const feed = parser.push("data: a\r\ndata: b\r\n\r\n");
    assert.equal(feed.messages[0]?.data, "a\nb");
    assert.equal(feed.messages[0]?.event, "message");
  });
});

describe("événements ILLWATCH", () => {
  it("convertit un message valide et rejette le reste", () => {
    const event = toLiveEvent({
      id: "x",
      event: "feed.collected",
      data: '{"id":"e1","kind":"feed.collected","data":{"feed_id":"f"},"at":"2026-10-10T08:00:00Z"}',
    });
    assert.deepEqual(event, {
      id: "e1",
      kind: "feed.collected",
      data: { feed_id: "f" },
      at: "2026-10-10T08:00:00Z",
    });
    assert.equal(toLiveEvent({ id: null, event: "x", data: "pas du json" }), null);
  });

  it("associe chaque type aux données à relire", () => {
    assert.deepEqual(queriesFor("alert.created"), [["dashboard"], ["alerts"], ["cves"]]);
    assert.deepEqual(queriesFor("feed.collected"), [["dashboard"], ["feeds"], ["indicators"]]);
    assert.deepEqual(queriesFor("inconnu"), []);
  });
});
