import { api } from "./client";
import type {
  DetonationJob,
  DetonationProvider,
  DetonationProviderCreate,
  DetonationProviderUpdate,
  Page,
} from "@/types/api";

export interface DetonationSubmitRequest {
  sha256: string;
  provider_id?: string | null;
  /** Optional base64-encoded sample bytes; omit to let the manager
   * pull from object storage. */
  sample_b64?: string | null;
}

export const detonationApi = {
  listProviders: () => api<DetonationProvider[]>("/api/detonation/providers"),
  createProvider: (body: DetonationProviderCreate) =>
    api<DetonationProvider>("/api/detonation/providers", { method: "POST", body }),
  updateProvider: (id: string, body: DetonationProviderUpdate) =>
    api<DetonationProvider>(`/api/detonation/providers/${id}`, { method: "PATCH", body }),
  removeProvider: (id: string) =>
    api<void>(`/api/detonation/providers/${id}`, { method: "DELETE" }),

  listJobs: (params: { sha256?: string; limit?: number; offset?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.sha256) qs.set("sha256", params.sha256);
    if (params.limit != null) qs.set("limit", String(params.limit));
    if (params.offset != null) qs.set("offset", String(params.offset));
    const suffix = qs.toString();
    return api<Page<DetonationJob>>(`/api/detonation/jobs${suffix ? `?${suffix}` : ""}`);
  },
  submit: (body: DetonationSubmitRequest) =>
    api<DetonationJob>("/api/detonation/submit", { method: "POST", body }),
};
