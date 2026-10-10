// Connexion temps réel à `GET /api/v1/stream` (ADR-016).
// Chaque événement dit « telle donnée a changé » : les requêtes concernées sont relues par
// l'API REST, avec les droits de l'utilisateur. En pause, rien n'est relu ; les changements
// s'accumulent et sont appliqués à la reprise.
import { useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { API, refreshSession } from "../api/http";
import { getAccessToken } from "../auth/tokens";
import { SseParser, queriesFor, toLiveEvent, type LiveEvent } from "./sse";

export type LiveStatus = "connecting" | "live" | "offline";

interface RealtimeValue {
  status: LiveStatus;
  paused: boolean;
  pending: number;
  lastEventAt: Date | null;
  recent: LiveEvent[];
  togglePause: () => void;
}

const RealtimeContext = createContext<RealtimeValue | null>(null);

const FLUSH_DELAY_MS = 1000; // regroupe les rafales (une collecte = plusieurs événements)
const MAX_DELAY_MS = 30_000;
const RECENT_LIMIT = 30;

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      clearTimeout(timer);
      resolve();
    });
  });

export function RealtimeProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const [paused, setPaused] = useState(false);
  const [pending, setPending] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<Date | null>(null);
  const [recent, setRecent] = useState<LiveEvent[]>([]);

  const pausedRef = useRef(false);
  const waiting = useRef(new Set<string>()); // clés à relire (JSON)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flush = useCallback(() => {
    timer.current = null;
    const keys = [...waiting.current];
    waiting.current.clear();
    if (keys.includes("*")) {
      void queryClient.invalidateQueries();
      return;
    }
    for (const key of keys) {
      void queryClient.invalidateQueries({ queryKey: JSON.parse(key) as string[] });
    }
  }, [queryClient]);

  const handle = useCallback(
    (event: LiveEvent) => {
      const keys = event.kind === "resync" ? ["*"] : queriesFor(event.kind).map((k) => JSON.stringify(k));
      if (keys.length === 0) return;
      keys.forEach((key) => waiting.current.add(key));
      setLastEventAt(new Date());
      setRecent((list) => [event, ...list].slice(0, RECENT_LIMIT));
      if (pausedRef.current) {
        setPending((n) => n + 1);
      } else if (timer.current === null) {
        timer.current = setTimeout(flush, FLUSH_DELAY_MS);
      }
    },
    [flush],
  );

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;

    async function connect(): Promise<"expired" | "closed"> {
      if (!getAccessToken() && !(await refreshSession())) throw new Error("session");
      let response = await open();
      if (response.status === 401 && (await refreshSession())) response = await open();
      if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`);

      setStatus("live");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      const parser = new SseParser();
      let outcome: "expired" | "closed" = "closed";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        for (const message of parser.push(decoder.decode(value, { stream: true })).messages) {
          if (message.event === "expired") {
            outcome = "expired";
            continue;
          }
          const event = toLiveEvent(message);
          if (event) handle(event);
        }
      }
      return outcome;
    }

    function open(): Promise<Response> {
      return fetch(`${API}/stream`, {
        headers: { Authorization: `Bearer ${getAccessToken() ?? ""}`, Accept: "text/event-stream" },
        cache: "no-store",
        signal,
      });
    }

    void (async () => {
      let delay = 1000;
      while (!signal.aborted) {
        setStatus((s) => (s === "live" ? s : "connecting"));
        const startedAt = Date.now();
        try {
          const outcome = await connect();
          // Flux refermé presque aussitôt : on attend avant de recommencer (pas de boucle serrée).
          if (Date.now() - startedAt < 5000) {
            await sleep(delay, signal);
            delay = Math.min(delay * 2, MAX_DELAY_MS);
          } else {
            delay = 1000;
          }
          // Jeton expiré : on le renouvelle et on se reconnecte aussitôt.
          if (outcome === "expired") await refreshSession();
          // Après une coupure, des événements ont pu manquer : tout relire.
          waiting.current.add("*");
          if (!pausedRef.current) flush();
        } catch {
          if (signal.aborted) return;
          setStatus("offline");
          await sleep(delay, signal);
          delay = Math.min(delay * 2, MAX_DELAY_MS);
        }
      }
    })();

    return () => {
      controller.abort();
      if (timer.current !== null) clearTimeout(timer.current);
    };
  }, [flush, handle]);

  const togglePause = useCallback(() => {
    const next = !pausedRef.current;
    pausedRef.current = next;
    setPaused(next);
    if (!next) {
      setPending(0);
      if (waiting.current.size > 0) flush();
    }
  }, [flush]);

  const value = useMemo(
    () => ({ status, paused, pending, lastEventAt, recent, togglePause }),
    [status, paused, pending, lastEventAt, recent, togglePause],
  );
  return <RealtimeContext.Provider value={value}>{children}</RealtimeContext.Provider>;
}

export function useRealtime(): RealtimeValue {
  const value = useContext(RealtimeContext);
  if (!value) throw new Error("useRealtime hors de RealtimeProvider");
  return value;
}
