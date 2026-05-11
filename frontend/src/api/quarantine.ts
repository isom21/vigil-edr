import { api } from "./client";
import type { Page, QuarantineStatus, QuarantinedFile } from "@/types/api";

export interface QuarantineListParams {
  status_?: QuarantineStatus;
  limit?: number;
  offset?: number;
}

export const quarantineApi = {
  listForHost: (hostId: string, params: QuarantineListParams = {}) =>
    api<Page<QuarantinedFile>>(`/api/hosts/${hostId}/quarantined`, {
      query: params as Record<string, string | number>,
    }),
  // M22.d: fleet-wide list.
  list: (params: QuarantineListParams & { sha256?: string } = {}) =>
    api<Page<QuarantinedFile>>(`/api/quarantined`, {
      query: params as Record<string, string | number>,
    }),
  release: (id: string, body: { target_path?: string | null } = {}) =>
    api<QuarantinedFile>(`/api/quarantined/${id}/release`, { method: "POST", body }),
  remove: (id: string) => api<void>(`/api/quarantined/${id}`, { method: "DELETE" }),
};
