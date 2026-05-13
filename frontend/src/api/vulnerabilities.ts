import { api } from "./client";
import type { HostVulnerability, Page, Vulnerability } from "@/types/api";

export interface VulnListParams {
  host_id?: string;
  cve_id?: string;
  severity?: string;
  include_suppressed?: boolean;
  limit?: number;
  offset?: number;
}

export const vulnerabilitiesApi = {
  list: (params: VulnListParams = {}) =>
    api<Page<HostVulnerability>>("/api/vulnerabilities", {
      query: params as Record<string, string | number | boolean>,
    }),
  getCve: (cveId: string) => api<Vulnerability>(`/api/vulnerabilities/${cveId}`),
  listForHost: (hostId: string, params: Omit<VulnListParams, "host_id"> = {}) =>
    api<Page<HostVulnerability>>(`/api/hosts/${hostId}/vulnerabilities`, {
      query: params as Record<string, string | number | boolean>,
    }),
  suppress: (id: string, reason?: string) =>
    api<HostVulnerability>(`/api/host-vulnerabilities/${id}/suppress`, {
      method: "POST",
      body: { reason },
    }),
};
