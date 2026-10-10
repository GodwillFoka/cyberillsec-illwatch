// Actions de triage. Après chaque action, les données concernées sont relues (le flux temps
// réel préviendra aussi les autres analystes connectés).
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiPost } from "./http";
import type { Alert, IncidentDetail } from "./types";

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
