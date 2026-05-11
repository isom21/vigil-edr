import { api } from "./client";
import type { Page, RuleGroup, RuleGroupCreate, RuleGroupUpdate, RuleKind } from "@/types/api";

export interface RuleGroupListParams {
  kind?: RuleKind;
  q?: string;
  limit?: number;
  offset?: number;
}

export const ruleGroupsApi = {
  list: (params: RuleGroupListParams = {}) =>
    api<Page<RuleGroup>>("/api/rule-groups", {
      query: params as Record<string, string | number>,
    }),
  get: (id: string) => api<RuleGroup>(`/api/rule-groups/${id}`),
  create: (body: RuleGroupCreate) => api<RuleGroup>("/api/rule-groups", { method: "POST", body }),
  update: (id: string, body: RuleGroupUpdate) =>
    api<RuleGroup>(`/api/rule-groups/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/rule-groups/${id}`, { method: "DELETE" }),
};
