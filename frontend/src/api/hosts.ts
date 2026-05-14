import { api } from "./client";
import type {
  AttestationEvent,
  AttestationGolden,
  Host,
  HostDetail,
  HostStatus,
  LiveTelemetryPage,
  OsFamily,
  Page,
  StatBucket,
} from "@/types/api";

export interface HostListParams {
  status_?: HostStatus;
  os_family?: OsFamily;
  q?: string;
  sort?: string;
  limit?: number;
  offset?: number;
}

export type HostStatsBucket = "status" | "os_family" | "agent_version" | "last_seen";

export const hostsApi = {
  list: (params: HostListParams = {}) =>
    api<Page<Host>>("/api/hosts", { query: params as Record<string, string | number> }),
  get: (id: string) => api<HostDetail>(`/api/hosts/${id}`),
  update: (id: string, body: { policy_id?: string | null; status?: HostStatus }) =>
    api<Host>(`/api/hosts/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/hosts/${id}`, { method: "DELETE" }),
  stats: (bucket: HostStatsBucket) => api<StatBucket[]>("/api/hosts/stats", { query: { bucket } }),
  telemetry: (id: string, params: { since?: string; limit?: number } = {}) =>
    api<LiveTelemetryPage>(`/api/hosts/${id}/telemetry`, {
      query: params as Record<string, string | number>,
    }),
  // Phase 4 #4.10 — TPM attestation endpoints. Mutations are admin-
  // only; reads are analyst+. The host detail page disables the
  // buttons for non-admins; the backend re-enforces the role.
  requestAttestation: (id: string) =>
    api<{ command_id: string; nonce: string }>(`/api/hosts/${id}/attestation/request`, {
      method: "POST",
    }),
  promoteAttestation: (id: string) =>
    api<AttestationGolden>(`/api/hosts/${id}/attestation/promote`, { method: "POST" }),
  listAttestationEvents: (id: string, params: { limit?: number; offset?: number } = {}) =>
    api<Page<AttestationEvent>>(`/api/hosts/${id}/attestation/events`, {
      query: params as Record<string, string | number>,
    }),
};
