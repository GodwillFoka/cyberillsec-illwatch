import type { UseQueryResult } from "@tanstack/react-query";
import type { ReactNode } from "react";

/** Chargement, erreur ou contenu : une donnée absente n'est jamais remplacée par une valeur inventée. */
export function QueryState<T>({
  query,
  children,
  empty,
}: {
  query: UseQueryResult<T>;
  children: (data: T) => ReactNode;
  empty?: (data: T) => boolean;
}) {
  if (query.isPending) return <p className="empty">Chargement…</p>;
  if (query.isError) {
    return (
      <p className="notice error" role="alert">
        Données indisponibles : {query.error.message}
      </p>
    );
  }
  if (empty?.(query.data)) return <p className="empty">Rien à afficher pour le moment.</p>;
  return <>{children(query.data)}</>;
}
