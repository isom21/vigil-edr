import { api } from "./client";
import type { Honeytoken, HoneytokenCreate, HoneytokenHit, HoneytokenUpdate } from "@/types/api";

export const honeytokensApi = {
  list: (params?: { host_group_id?: string }) =>
    api<Honeytoken[]>("/api/honeytokens", { query: params }),
  create: (body: HoneytokenCreate) => api<Honeytoken>("/api/honeytokens", { method: "POST", body }),
  update: (id: string, body: HoneytokenUpdate) =>
    api<Honeytoken>(`/api/honeytokens/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/honeytokens/${id}`, { method: "DELETE" }),
  hits: (id: string, params?: { limit?: number }) =>
    api<HoneytokenHit[]>(`/api/honeytokens/${id}/hits`, { query: params }),
};
