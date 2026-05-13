import { api } from "./client";
import type { IntelFeed, IntelFeedCreate, IntelFeedUpdate, Page } from "@/types/api";

export const intelApi = {
  list: (params: { limit?: number; offset?: number } = {}) =>
    api<Page<IntelFeed>>("/api/intel/feeds", {
      query: params as Record<string, string | number>,
    }),
  get: (id: string) => api<IntelFeed>(`/api/intel/feeds/${id}`),
  create: (body: IntelFeedCreate) => api<IntelFeed>("/api/intel/feeds", { method: "POST", body }),
  update: (id: string, body: IntelFeedUpdate) =>
    api<IntelFeed>(`/api/intel/feeds/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/intel/feeds/${id}`, { method: "DELETE" }),
  triggerPull: (id: string) => api<IntelFeed>(`/api/intel/feeds/${id}/pull`, { method: "POST" }),
};
