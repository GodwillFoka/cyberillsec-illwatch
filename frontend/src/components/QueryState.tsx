import type { UseQueryResult } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { messages } from "../i18n/common.i18n";

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
  if (query.isPending) return <p className="empty">{messages("loading")}</p>;
  if (query.isError) {
    return (
      <p className="notice error" role="alert">
        {messages("unavailable", { message: query.error.message })}
      </p>
    );
  }
  if (empty?.(query.data)) return <p className="empty">{messages("nothing")}</p>;
  return <>{children(query.data)}</>;
}
