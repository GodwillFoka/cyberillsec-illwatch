import { describe, expect, it } from "vitest";

import { SseParser, queriesFor, toLiveEvent } from "./sse";

describe("SseParser", () => {
  it("assemble un message reçu en plusieurs morceaux", () => {
    const parser = new SseParser();
    expect(parser.push("retry: 5000\n: illwatch\n\nid: a1\nevent: alert.cr").messages).toEqual([]);
    const feed = parser.push('eated\ndata: {"kind":"alert.created"}\n\n');
    expect(feed.messages).toEqual([
      { id: "a1", event: "alert.created", data: '{"kind":"alert.created"}' },
    ]);
  });

  it("lit le délai de reconnexion et ignore les battements", () => {
    const parser = new SseParser();
    const feed = parser.push("retry: 5000\n\n: ping\n\n");
    expect(feed.retryMs).toBe(5000);
    expect(feed.messages).toEqual([]);
  });

  it("accepte les fins de ligne CRLF et les données sur plusieurs lignes", () => {
    const parser = new SseParser();
    const feed = parser.push("data: a\r\ndata: b\r\n\r\n");
    expect(feed.messages[0]?.data).toBe("a\nb");
    expect(feed.messages[0]?.event).toBe("message");
  });
});

describe("événements ILLWATCH", () => {
  it("convertit un message valide et rejette le reste", () => {
    const event = toLiveEvent({
      id: "x",
      event: "feed.collected",
      data: '{"id":"e1","kind":"feed.collected","data":{"feed_id":"f"},"at":"2026-10-10T08:00:00Z"}',
    });
    expect(event).toEqual({
      id: "e1",
      kind: "feed.collected",
      data: { feed_id: "f" },
      at: "2026-10-10T08:00:00Z",
    });
    expect(toLiveEvent({ id: null, event: "x", data: "pas du json" })).toBeNull();
  });

  it("associe chaque type aux données à relire", () => {
    expect(queriesFor("alert.created")).toEqual([["dashboard"], ["alerts"]]);
    expect(queriesFor("inconnu")).toEqual([]);
  });
});
