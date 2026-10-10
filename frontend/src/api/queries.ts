// Requêtes TanStack Query partagées. Les clés commencent par le domaine (« dashboard »,
// « alerts », « incidents », « feeds ») : le flux temps réel relit un domaine entier.
import { useQuery } from "@tanstack/react-query";

import { useRealtime } from "../realtime/RealtimeProvider";
import { apiGet } from "./http";
import type {
  Activity,
  AlertPage,
  FeedHealth,
  IncidentPage,
  Metric,
  Series,
  Summary,
  SeriesWindow,
} from "./types";

/** Sans flux temps réel, les données sont relues toutes les minutes. */
function useFallbackInterval(): number | false {
  const { status, paused } = useRealtime();
  return status === "live" || paused ? false : 60_000;
}

export function useSummary() {
  const refetchInterval = useFallbackInterval();
  return useQuery({
    queryKey: ["dashboard", "summary"],
    queryFn: ({ signal }) => apiGet<Summary>("/dashboard/summary", undefined, signal),
    refetchInterval,
  });
}

export function useSeries(metric: Metric, window: SeriesWindow) {
  const refetchInterval = useFallbackInterval();
  return useQuery({
    queryKey: ["dashboard", "timeseries", metric, window],
    queryFn: ({ signal }) => apiGet<Series>("/dashboard/timeseries", { metric, window }, signal),
    refetchInterval,
  });
}

export function useRecentActivity(hours = 24) {
  const refetchInterval = useFallbackInterval();
  return useQuery({
    queryKey: ["dashboard", "recent", hours],
    queryFn: ({ signal }) => apiGet<Activity[]>("/dashboard/recent", { hours }, signal),
    refetchInterval,
  });
}

export function useFeedsHealth() {
  const refetchInterval = useFallbackInterval();
  return useQuery({
    queryKey: ["feeds", "health"],
    queryFn: ({ signal }) => apiGet<FeedHealth[]>("/feeds/health", undefined, signal),
    refetchInterval,
  });
}

export function usePendingAlerts(limit = 100) {
  const refetchInterval = useFallbackInterval();
  return useQuery({
    queryKey: ["alerts", "pending", limit],
    queryFn: ({ signal }) =>
      apiGet<AlertPage>("/alerts", { acknowledged: false, limit }, signal),
    refetchInterval,
  });
}

export function useOpenIncidents(limit = 20) {
  const refetchInterval = useFallbackInterval();
  return useQuery({
    queryKey: ["incidents", "open", limit],
    queryFn: ({ signal }) =>
      apiGet<IncidentPage>("/incidents", { open_only: true, limit }, signal),
    refetchInterval,
  });
}
