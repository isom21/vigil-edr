import { api } from "./client";
import type { ArchiveJob } from "@/types/api";

export const archiveApi = {
  // Frozen-only list — what the main "Cold archive" table renders.
  listFrozen: (params: { limit?: number } = {}) =>
    api<ArchiveJob[]>("/api/archive", {
      query: params as Record<string, string | number>,
    }),
  // Full job ledger including in-flight / failed rows.
  listJobs: (params: { limit?: number } = {}) =>
    api<ArchiveJob[]>("/api/archive/jobs", {
      query: params as Record<string, string | number>,
    }),
  rehydrate: (id: string) => api<ArchiveJob>(`/api/archive/${id}/rehydrate`, { method: "POST" }),
};
