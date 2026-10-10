// Requêtes TanStack Query partagées. Les clés commencent par le domaine (« dashboard »,
// « alerts », « incidents », « feeds ») : le flux temps réel relit un domaine entier.
import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { useRealtime } from "../realtime/RealtimeProvider";
import { apiGet } from "./http";
import type {
  Activity,
  AlertPage,
  CveDetail,
  IncidentDetail,
  IndicatorDetail,
  IndicatorPage,
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

/** Alertes du triage : à traiter (non acquittées) ou toutes les récentes. */
export function useTriageAlerts(scope: "pending" | "all") {
  const refetchInterval = useFallbackInterval();
  return useQuery({
    queryKey: ["alerts", "triage", scope],
    queryFn: ({ signal }) =>
      apiGet<AlertPage>(
        "/alerts",
        { acknowledged: scope === "pending" ? false : undefined, limit: 200 },
        signal,
      ),
    refetchInterval,
  });
}

/** Détail d'une CVE : décomposition du score et historique de priorité. */
export function useCveDetail(cveId: string | undefined) {
  return useQuery({
    queryKey: ["cves", "detail", cveId],
    queryFn: ({ signal }) => apiGet<CveDetail>(`/cves/${encodeURIComponent(cveId ?? "")}`, undefined, signal),
    enabled: Boolean(cveId),
    staleTime: 5 * 60_000,
  });
}

export interface IncidentFilters {
  openOnly: boolean;
  status?: string;
  severity?: string;
}

export function useIncidents(filters: IncidentFilters) {
  const refetchInterval = useFallbackInterval();
  return useQuery({
    queryKey: ["incidents", "list", filters],
    queryFn: ({ signal }) =>
      apiGet<IncidentPage>(
        "/incidents",
        {
          open_only: filters.openOnly,
          status: filters.status || undefined,
          severity: filters.severity || undefined,
          limit: 200,
        },
        signal,
      ),
    refetchInterval,
  });
}

export function useIncident(incidentId: string) {
  const refetchInterval = useFallbackInterval();
  return useQuery({
    queryKey: ["incidents", "detail", incidentId],
    queryFn: ({ signal }) => apiGet<IncidentDetail>(`/incidents/${incidentId}`, undefined, signal),
    refetchInterval,
  });
}

export function useIndicator(indicatorId: string) {
  return useQuery({
    queryKey: ["indicators", "detail", indicatorId],
    queryFn: ({ signal }) => apiGet<IndicatorDetail>(`/indicators/${indicatorId}`, undefined, signal),
    staleTime: 5 * 60_000,
  });
}

export interface IndicatorFilters {
  /** Recherche exacte, normalisée par le serveur (`evil[.]com` trouve `evil.com`). */
  value?: string;
  type?: string;
  minSeverity?: string;
  feedId?: string;
  /** « actifs » : non expirés ; « expirés » ; « tous ». */
  state: "actifs" | "expires" | "tous";
}

export const INDICATOR_PAGE_SIZE = 50;

export function useIndicators(filters: IndicatorFilters, offset: number) {
  return useQuery({
    queryKey: ["indicators", "list", filters, offset],
    queryFn: ({ signal }) =>
      apiGet<IndicatorPage>(
        "/indicators",
        {
          value: filters.value || undefined,
          type: filters.type || undefined,
          min_severity: filters.minSeverity || undefined,
          feed_id: filters.feedId || undefined,
          active: filters.state === "tous" ? undefined : filters.state === "actifs",
          limit: INDICATOR_PAGE_SIZE,
          offset,
        },
        signal,
      ),
    // Changement de page ou de filtre : l'ancienne page reste affichée pendant la lecture.
    placeholderData: keepPreviousData,
  });
}

/** Incidents auxquels un IOC (ou une CVE) est associé. */
export function useLinkedIncidents(link: { indicatorId?: string; cveId?: string }) {
  return useQuery({
    queryKey: ["incidents", "linked", link],
    queryFn: ({ signal }) =>
      apiGet<IncidentPage>(
        "/incidents",
        { indicator_id: link.indicatorId, cve_id: link.cveId, limit: 50 },
        signal,
      ),
    enabled: Boolean(link.indicatorId || link.cveId),
  });
}
