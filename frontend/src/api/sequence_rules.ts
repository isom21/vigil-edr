import { api } from "./client";
import type { Page, SequenceRule, SequenceRuleCreate, SequenceRuleUpdate } from "@/types/api";

export const sequenceRulesApi = {
  list: (params: { enabled?: boolean; limit?: number; offset?: number } = {}) =>
    api<Page<SequenceRule>>("/api/sequence-rules", {
      query: params as Record<string, string | number | boolean>,
    }),
  get: (id: string) => api<SequenceRule>(`/api/sequence-rules/${id}`),
  create: (body: SequenceRuleCreate) =>
    api<SequenceRule>("/api/sequence-rules", { method: "POST", body }),
  update: (id: string, body: SequenceRuleUpdate) =>
    api<SequenceRule>(`/api/sequence-rules/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/sequence-rules/${id}`, { method: "DELETE" }),
};
