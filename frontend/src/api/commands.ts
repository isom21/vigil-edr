import { api } from "./client";
import type { Command, CommandKind, CommandStatus, Page, StatBucket } from "@/types/api";

export interface CommandQueueBody {
  kind: CommandKind;
  payload: Record<string, unknown>;
}

export interface CommandListParams {
  status_?: CommandStatus;
  kind?: CommandKind;
  sort?: string;
  limit?: number;
  offset?: number;
}

export type CommandStatsBucket = "status" | "kind";

export const commandsApi = {
  // Cross-host listing (admin sees all, others scoped by group).
  listAll: (params: CommandListParams = {}) =>
    api<Page<Command>>("/api/commands", { query: params as Record<string, string | number> }),

  // Per-host listing.
  listForHost: (hostId: string, params: CommandListParams = {}) =>
    api<Page<Command>>(`/api/hosts/${hostId}/commands`, {
      query: params as Record<string, string | number>,
    }),

  // Queue a new command.
  queue: (hostId: string, body: CommandQueueBody) =>
    api<Command>(`/api/hosts/${hostId}/commands`, { method: "POST", body }),

  // Aggregate stats for the chart strip.
  stats: (bucket: CommandStatsBucket) =>
    api<StatBucket[]>("/api/commands/stats", { query: { bucket } }),
};
