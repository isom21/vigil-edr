import { api } from "./client";
import type {
  HuntAdhocRequest,
  HuntRun,
  HuntRunResult,
  Page,
  SavedHunt,
  SavedHuntCreate,
  SavedHuntUpdate,
} from "@/types/api";

export const huntApi = {
  runAdhoc: (body: HuntAdhocRequest) =>
    api<HuntRunResult>("/api/hunt/run", { method: "POST", body }),
  listSaved: (params: { limit?: number; offset?: number } = {}) =>
    api<Page<SavedHunt>>("/api/hunt/saved", {
      query: params as Record<string, string | number>,
    }),
  getSaved: (id: string) => api<SavedHunt>(`/api/hunt/saved/${id}`),
  createSaved: (body: SavedHuntCreate) =>
    api<SavedHunt>("/api/hunt/saved", { method: "POST", body }),
  updateSaved: (id: string, body: SavedHuntUpdate) =>
    api<SavedHunt>(`/api/hunt/saved/${id}`, { method: "PATCH", body }),
  removeSaved: (id: string) => api<void>(`/api/hunt/saved/${id}`, { method: "DELETE" }),
  runSaved: (id: string) =>
    api<HuntRunResult>(`/api/hunt/saved/${id}/run`, { method: "POST" }),
  listRuns: (id: string, params: { limit?: number; offset?: number } = {}) =>
    api<Page<HuntRun>>(`/api/hunt/saved/${id}/runs`, {
      query: params as Record<string, string | number>,
    }),
};
