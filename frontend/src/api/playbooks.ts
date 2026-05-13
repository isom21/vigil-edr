import { api } from "./client";
import type { Page, Playbook, PlaybookCreate, PlaybookRun, PlaybookUpdate } from "@/types/api";

export const playbooksApi = {
  list: (params: { enabled?: boolean; limit?: number; offset?: number } = {}) =>
    api<Page<Playbook>>("/api/playbooks", {
      query: params as Record<string, string | number | boolean>,
    }),
  get: (id: string) => api<Playbook>(`/api/playbooks/${id}`),
  create: (body: PlaybookCreate) => api<Playbook>("/api/playbooks", { method: "POST", body }),
  update: (id: string, body: PlaybookUpdate) =>
    api<Playbook>(`/api/playbooks/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/playbooks/${id}`, { method: "DELETE" }),
  listRuns: (id: string, params: { limit?: number; offset?: number } = {}) =>
    api<Page<PlaybookRun>>(`/api/playbooks/${id}/runs`, {
      query: params as Record<string, string | number | boolean>,
    }),
  getRun: (runId: string) => api<PlaybookRun>(`/api/playbooks/runs/${runId}`),
};
