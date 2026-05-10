import { api } from "./client";
import type { Page, Rule, RuleCreate, RuleKind, StatBucket } from "@/types/api";

export interface RuleListParams {
  kind?: RuleKind;
  enabled?: boolean;
  q?: string;
  sort?: string;
  limit?: number;
  offset?: number;
}

export type RuleStatsBucket = "kind" | "severity" | "enabled";

export const rulesApi = {
  list: (params: RuleListParams = {}) =>
    api<Page<Rule>>("/api/rules", { query: params as Record<string, string | number | boolean> }),
  get: (id: string) => api<Rule>(`/api/rules/${id}`),
  create: (body: RuleCreate) => api<Rule>("/api/rules", { method: "POST", body }),
  update: (id: string, body: Partial<RuleCreate>) =>
    api<Rule>(`/api/rules/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/rules/${id}`, { method: "DELETE" }),
  stats: (bucket: RuleStatsBucket) => api<StatBucket[]>("/api/rules/stats", { query: { bucket } }),
};
