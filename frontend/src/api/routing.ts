import { api } from "./client";
import type { RoutingRule, RuleKind, Severity } from "@/types/api";

export interface RoutingRuleCreateBody {
  name: string;
  min_severity?: Severity;
  rule_kind?: RuleKind | null;
  host_group_id?: string | null;
  channel_ids: string[];
  enabled?: boolean;
}

export interface RoutingRuleUpdateBody {
  name?: string;
  min_severity?: Severity;
  rule_kind?: RuleKind | null;
  host_group_id?: string | null;
  channel_ids?: string[];
  enabled?: boolean;
}

export const routingApi = {
  list: () => api<RoutingRule[]>("/api/notifications/rules"),
  get: (id: string) => api<RoutingRule>(`/api/notifications/rules/${id}`),
  create: (body: RoutingRuleCreateBody) =>
    api<RoutingRule>("/api/notifications/rules", { method: "POST", body }),
  update: (id: string, body: RoutingRuleUpdateBody) =>
    api<RoutingRule>(`/api/notifications/rules/${id}`, {
      method: "PATCH",
      body,
    }),
  remove: (id: string) => api<void>(`/api/notifications/rules/${id}`, { method: "DELETE" }),
};
