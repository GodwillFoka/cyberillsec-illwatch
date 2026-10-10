import { useRef } from "react";

const FRESH_MS = 2500;

/**
 * Identifiants apparus depuis l'affichage précédent : leur ligne est surlignée 2,5 s, sans
 * déplacer la ligne lue (système de design v6). `ids` vaut `undefined` tant que les données
 * ne sont pas chargées : rien n'est surligné au premier affichage.
 */
export function useFresh(ids: string[] | undefined): Set<string> {
  const firstSeen = useRef<Map<string, number> | null>(null);
  if (!ids) return new Set();
  const now = Date.now();
  if (firstSeen.current === null) {
    firstSeen.current = new Map(ids.map((id) => [id, 0]));
  } else {
    for (const id of ids) {
      if (!firstSeen.current.has(id)) firstSeen.current.set(id, now);
    }
    if (firstSeen.current.size > 5000) firstSeen.current = new Map(ids.map((id) => [id, 0]));
  }
  const seen = firstSeen.current;
  return new Set(ids.filter((id) => now - (seen.get(id) ?? 0) < FRESH_MS));
}
