// Actions de triage. Après chaque action, les données concernées sont relues (le flux temps
// réel préviendra aussi les autres analystes connectés).
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiDelete, apiPost, apiSend } from "./http";
import type {
  Account,
  Alert,
  Asset,
  AssetWrite,
  Correlation,
  CorrelationRun,
  Feed,
  Hunt,
  HuntDetail,
  IncidentDetail,
  IncidentEvent,
  IncidentHunt,
  IngestResult,
  Exclusion,
  Campaign,
} from "./types";

export function useAcknowledgeAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (alertId: string) => apiPost<Alert>(`/alerts/${encodeURIComponent(alertId)}/ack`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export function useOpenIncidentFromAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (alertId: string) => apiPost<IncidentDetail>(`/alerts/${encodeURIComponent(alertId)}/incident`),
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
      apiPost<IncidentDetail>(`/incidents/${encodeURIComponent(incidentId)}/transitions`, body),
  );
}

export function useAddNote(incidentId: string) {
  return useIncidentMutation((body: { message: string; kind: "COMMENT" | "ACTION_TAKEN" }) =>
    apiPost<IncidentEvent>(`/incidents/${encodeURIComponent(incidentId)}/notes`, body),
  );
}

export function useAssign(incidentId: string) {
  return useIncidentMutation((userId: string | null) =>
    apiSend<IncidentDetail>("PUT", `/incidents/${encodeURIComponent(incidentId)}/assignee`, { user_id: userId }),
  );
}

export function useLinkCve(incidentId: string) {
  return useIncidentMutation((cveId: string) =>
    apiPost<{ created: boolean }>(`/incidents/${encodeURIComponent(incidentId)}/cves`, { cve_id: cveId }),
  );
}

export function useLinkIndicator(incidentId: string) {
  return useIncidentMutation((value: string) =>
    apiPost<{ created: boolean }>(`/incidents/${encodeURIComponent(incidentId)}/indicators`, { value }),
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

export type AttachTarget = { indicatorId: string } | { cveId: string };

/** Associe un IOC ou une CVE à un incident ouvert, depuis sa fiche (RF-20). */
export function useAttachToIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ incidentId, target }: { incidentId: string; target: AttachTarget }) =>
      "indicatorId" in target
        ? apiPost<{ created: boolean }>(`/incidents/${encodeURIComponent(incidentId)}/indicators`, {
            indicator_id: target.indicatorId,
          })
        : apiPost<{ created: boolean }>(`/incidents/${encodeURIComponent(incidentId)}/cves`, { cve_id: target.cveId }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

/** Ouvre un incident de remédiation déjà associé à sa CVE : une seule écriture, tout ou rien. */
export function useOpenIncidentForCve() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ cveId, severity, description }: { cveId: string; severity: string; description: string }) =>
      apiPost<IncidentDetail>("/incidents", {
        title: `Remédiation ${cveId}`,
        description,
        severity,
        cve_ids: [cveId],
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export interface HuntRequest {
  observables: string[];
  assets: string[];
  rules: string[];
}

/** Lance une session de chasse (ADMIN, ANALYST) : exécutée pendant la requête, puis enregistrée. */
export function useRunHunt() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: HuntRequest) => apiPost<HuntDetail>("/hunting/sessions", body),
    onSuccess: (hunt) => {
      const { matches, ...summary } = hunt;
      void matches;
      // La nouvelle session entre tout de suite dans la liste : l'écran n'a pas à relire son
      // détail complet (toutes les correspondances) en attendant la relecture de la liste.
      queryClient.setQueryData<Hunt[]>(["hunts", "list"], (old) => [
        summary,
        ...(old ?? []).filter((h) => h.id !== summary.id),
      ]);
      void queryClient.invalidateQueries({ queryKey: ["hunts"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

// --- Sources CTI (ADMIN) -------------------------------------------------------------------

function useFeedsMutation<TVariables, TResult>(run: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: run,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["feeds"] });
      // La fiabilité d'une source change la confiance de ses IOC (ADR-017).
      void queryClient.invalidateQueries({ queryKey: ["indicators"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export interface FeedChanges {
  is_active?: boolean;
  polling_interval?: number;
  reliability?: string;
}

export function useUpdateFeed(feedId: string) {
  return useFeedsMutation((changes: FeedChanges) =>
    apiSend<Feed>("PATCH", `/feeds/${encodeURIComponent(feedId)}`, changes),
  );
}

export interface NewFeed {
  name: string;
  url: string;
  feed_type: string;
  polling_interval: number;
  reliability: string;
}

export function useCreateFeed() {
  return useFeedsMutation((body: NewFeed) => apiPost<Feed>("/feeds", body));
}

export function useDeleteFeed() {
  return useFeedsMutation((feedId: string) => apiDelete(`/feeds/${encodeURIComponent(feedId)}`));
}

// --- Comptes (ADMIN) -----------------------------------------------------------------------

function useAdminMutation<TVariables, TResult>(run: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: run,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["admin"] });
    },
  });
}

export interface NewAccount {
  username: string;
  email: string;
  role: string;
  password: string;
}

export function useCreateAccount() {
  return useAdminMutation((body: NewAccount) => apiPost<Account>("/users", body));
}

export function useUpdateAccount(userId: string) {
  return useAdminMutation((changes: { role?: string; is_active?: boolean }) =>
    apiSend<Account>("PATCH", `/users/${encodeURIComponent(userId)}`, changes),
  );
}

export function useResetPassword(userId: string) {
  return useAdminMutation((password: string) =>
    apiPost<{ revoked: number }>(`/users/${encodeURIComponent(userId)}/password`, { password }),
  );
}

export function useRevokeSessions(userId: string) {
  return useAdminMutation(() =>
    apiPost<{ revoked: number }>(`/users/${encodeURIComponent(userId)}/revoke-sessions`),
  );
}

// --- Corrélation (M8, ADR-020) ---------------------------------------------------------------

function useCorrelationMutation<TVariables, TResult>(run: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: run,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
      void queryClient.invalidateQueries({ queryKey: ["correlations"] });
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export function useSaveAsset(assetId: string | null) {
  return useCorrelationMutation((body: AssetWrite) =>
    assetId
      ? apiSend<Asset>("PUT", `/assets/${encodeURIComponent(assetId)}`, body)
      : apiPost<Asset>("/assets", body),
  );
}

export function useDeleteAsset() {
  return useCorrelationMutation((assetId: string) => apiDelete(`/assets/${encodeURIComponent(assetId)}`));
}

export function useRunCorrelation() {
  return useCorrelationMutation(() => apiPost<CorrelationRun>("/correlations/run"));
}

export function useAcknowledgeCorrelation() {
  return useCorrelationMutation((eventId: string) =>
    apiPost<Correlation>(`/correlations/${encodeURIComponent(eventId)}/ack`),
  );
}

export function useIncidentFromCorrelation() {
  return useCorrelationMutation((eventId: string) =>
    apiPost<{ incident_id: string; created: boolean }>(`/correlations/${encodeURIComponent(eventId)}/incident`),
  );
}

// --- M9 SOC Operations (ADR-022) ----------------------------------------------------------------

export function useEscalate(incidentId: string) {
  return useIncidentMutation((body: { reason: string }) =>
    apiPost<IncidentDetail>(`/incidents/${encodeURIComponent(incidentId)}/escalate`, body),
  );
}

export function useHuntFromIncident(incidentId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (observables: string[]) =>
      apiPost<IncidentHunt>(`/incidents/${encodeURIComponent(incidentId)}/hunt`, { observables }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["hunts"] });
    },
  });
}

export interface NewExclusion {
  value: string;
  reason: string;
  incident_id?: string;
  days?: number;
}

function useExclusionMutation<TVariables, TResult>(run: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: run,
    onSuccess: () => {
      for (const key of ["exclusions", "indicators", "incidents", "correlations", "dashboard"]) {
        void queryClient.invalidateQueries({ queryKey: [key] });
      }
    },
  });
}

export function useCreateExclusion() {
  return useExclusionMutation((body: NewExclusion) => apiPost<Exclusion>("/exclusions", body));
}

export function useDeleteExclusion() {
  return useExclusionMutation((exclusionId: string) =>
    apiDelete(`/exclusions/${encodeURIComponent(exclusionId)}`),
  );
}

export function useFalsePositiveCorrelation() {
  return useExclusionMutation((body: { eventId: string; reason: string }) =>
    apiPost<Correlation>(`/correlations/${encodeURIComponent(body.eventId)}/false-positive`, {
      reason: body.reason,
    }),
  );
}

// --- M10 Campagnes (ADR-024) -----------------------------------------------------------------

function useCampaignMutation<TVariables, TResult>(run: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: run,
    onSuccess: () => {
      for (const key of ["campaigns", "correlations", "incidents", "hunts"]) {
        void queryClient.invalidateQueries({ queryKey: [key] });
      }
    },
  });
}

export function useCreateCampaign() {
  return useCampaignMutation((body: { name: string; description?: string; actor_id?: string }) =>
    apiPost<Campaign>("/campaigns", body),
  );
}

export function useAttachToCampaign(campaignId: string) {
  return useCampaignMutation((body: { values?: string[]; description_contains?: string }) =>
    apiPost<{ attached: number; unknown: number }>(
      `/campaigns/${encodeURIComponent(campaignId)}/indicators`,
      body,
    ),
  );
}

export function useDeleteCampaign() {
  return useCampaignMutation((campaignId: string) => apiDelete(`/campaigns/${encodeURIComponent(campaignId)}`));
}
