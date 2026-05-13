import { api } from "./client";
import type { Incident, IncidentDetail, IncidentStatus, Page } from "@/types/api";

export interface IncidentListParams {
  status?: IncidentStatus;
  host_id?: string;
  sort?: string;
  limit?: number;
  offset?: number;
}

export const incidentsApi = {
  list: (params: IncidentListParams = {}) =>
    api<Page<Incident>>("/api/incidents", { query: params as Record<string, string | number> }),
  get: (id: string) => api<IncidentDetail>(`/api/incidents/${id}`),
  changeState: (id: string, body: { to_state: IncidentStatus; comment?: string | null }) =>
    api<IncidentDetail>(`/api/incidents/${id}/state`, { method: "POST", body }),
  assign: (id: string, body: { assignee_id: string | null }) =>
    api<IncidentDetail>(`/api/incidents/${id}/assign`, { method: "POST", body }),
};
