// Actions de triage. Après chaque action, les données concernées sont relues (le flux temps
// réel préviendra aussi les autres analystes connectés).
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiPost, apiSend } from "./http";
import type { Alert, IncidentDetail, IncidentEvent, IngestResult } from "./types";

export function useAcknowledgeAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (alertId: string) => apiPost<Alert>(`/alerts/${alertId}/ack`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export function useOpenIncidentFromAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (alertId: string) => apiPost<IncidentDetail>(`/alerts/${alertId}/incident`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

function useIncidentMutation<TVariables, TResult>(run: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: run,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export interface NewIncident {
  title: string;
  description: string;
  severity: string;
}

export function useCreateIncident() {
  return useIncidentMutation((body: NewIncident) => apiPost<IncidentDetail>("/incidents", body));
}

export function useTransition(incidentId: string) {
  return useIncidentMutation(
    (body: { target: string; note?: string; closure_summary?: string }) =>
      apiPost<IncidentDetail>(`/incidents/${incidentId}/transitions`, body),
  );
}

export function useAddNote(incidentId: string) {
  return useIncidentMutation((body: { message: string; kind: "COMMENT" | "ACTION_TAKEN" }) =>
    apiPost<IncidentEvent>(`/incidents/${incidentId}/notes`, body),
  );
}

export function useAssign(incidentId: string) {
  return useIncidentMutation((userId: string | null) =>
    apiSend<IncidentDetail>("PUT", `/incidents/${incidentId}/assignee`, { user_id: userId }),
  );
}

export function useLinkCve(incidentId: string) {
  return useIncidentMutation((cveId: string) =>
    apiPost<{ created: boolean }>(`/incidents/${incidentId}/cves`, { cve_id: cveId }),
  );
}

export function useLinkIndicator(incidentId: string) {
  return useIncidentMutation((value: string) =>
    apiPost<{ created: boolean }>(`/incidents/${incidentId}/indicators`, { value }),
  );
}

export interface IndicatorBatch {
  values: string[];
  severity: string;
  description?: string;
}

/** Soumission d'un lot d'IOC (ADMIN, ANALYST) : normalisé, validé et dédupliqué par le serveur. */
export function useSubmitIndicators() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ values, severity, description }: IndicatorBatch) =>
      apiPost<IngestResult>("/indicators", {
        items: values.map((value) => ({ value, severity, description: description || undefined })),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["indicators"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

/** Associe un IOC à un incident ouvert, depuis l'écran Indicateurs. */
export function useAttachIndicator() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ incidentId, indicatorId }: { incidentId: string; indicatorId: string }) =>
      apiPost<{ created: boolean }>(`/incidents/${incidentId}/indicators`, {
        indicator_id: indicatorId,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}
