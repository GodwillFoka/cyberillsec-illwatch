// Analyse du format Server-Sent Events (WHATWG, § 9.2), alimentée par morceaux.
// `EventSource` ne permet pas d'envoyer l'en-tête Authorization : le flux est lu avec fetch.

export interface SseMessage {
  id: string | null;
  event: string;
  data: string;
}

export interface SseFeed {
  messages: SseMessage[];
  /** Délai de reconnexion demandé par le serveur (`retry:`), s'il en a envoyé un. */
  retryMs: number | null;
}

export class SseParser {
  private buffer = "";
  private eventType = "";
  private dataLines: string[] = [];
  private lastId: string | null = null;

  /** Ajoute un morceau de texte et renvoie les messages complets qu'il termine. */
  push(chunk: string): SseFeed {
    this.buffer += chunk;
    const out: SseFeed = { messages: [], retryMs: null };
    let newline: number;
    while ((newline = this.buffer.search(/\r\n|\r|\n/)) >= 0) {
      const line = this.buffer.slice(0, newline);
      const width = this.buffer.startsWith("\r\n", newline) ? 2 : 1;
      this.buffer = this.buffer.slice(newline + width);
      this.line(line, out);
    }
    return out;
  }

  private line(line: string, out: SseFeed): void {
    if (line === "") {
      if (this.dataLines.length > 0) {
        out.messages.push({
          id: this.lastId,
          event: this.eventType || "message",
          data: this.dataLines.join("\n"),
        });
      }
      this.eventType = "";
      this.dataLines = [];
      return;
    }
    if (line.startsWith(":")) return; // commentaire (battement)
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    switch (field) {
      case "event":
        this.eventType = value;
        break;
      case "data":
        this.dataLines.push(value);
        break;
      case "id":
        if (!value.includes("\0")) this.lastId = value;
        break;
      case "retry":
        if (/^\d+$/.test(value)) out.retryMs = Number(value);
        break;
      default:
        break;
    }
  }
}

/** Événement ILLWATCH tel que publié par `GET /api/v1/stream`. */
export interface LiveEvent {
  id: string;
  kind: string;
  data: Record<string, unknown>;
  at: string;
}

export function toLiveEvent(message: SseMessage): LiveEvent | null {
  try {
    const body = JSON.parse(message.data) as Partial<LiveEvent>;
    if (typeof body.kind !== "string") return null;
    return {
      id: typeof body.id === "string" ? body.id : (message.id ?? ""),
      kind: body.kind,
      data: body.data && typeof body.data === "object" ? body.data : {},
      at: typeof body.at === "string" ? body.at : new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

/** Requêtes à relire pour un type d'événement (clés TanStack Query). */
export function queriesFor(kind: string): string[][] {
  switch (kind) {
    case "alert.created":
    case "alert.acknowledged":
      return [["dashboard"], ["alerts"]];
    case "incident.created":
    case "incident.updated":
      return [["dashboard"], ["incidents"]];
    case "feed.collected":
      return [["dashboard"], ["feeds"]];
    case "hunt.completed":
      return [["dashboard"], ["hunts"]];
    default:
      return [];
  }
}
