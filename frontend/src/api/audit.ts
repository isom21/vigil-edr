import { api } from "./client";
import type { AuditEntry, Page } from "@/types/api";

export interface AuditListParams {
  action?: string;
  resource_type?: string;
  resource_id?: string;
  actor_kind?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export const auditApi = {
  list: (params: AuditListParams = {}) =>
    api<Page<AuditEntry>>("/api/audit", {
      query: params as Record<string, string | number>,
    }),
};
