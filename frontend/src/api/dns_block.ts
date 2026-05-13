import { api } from "./client";
import type {
  DnsBlockEntry,
  DnsBlockEntryCreate,
  DnsBlockBulkImport,
  DnsBlockBulkImportResult,
} from "@/types/api";

export const dnsBlockApi = {
  list: (params?: { host_group_id?: string }) =>
    api<DnsBlockEntry[]>("/api/dns-blocks", { query: params }),
  create: (body: DnsBlockEntryCreate) =>
    api<DnsBlockEntry>("/api/dns-blocks", { method: "POST", body }),
  remove: (id: string) => api<void>(`/api/dns-blocks/${id}`, { method: "DELETE" }),
  bulkImport: (body: DnsBlockBulkImport) =>
    api<DnsBlockBulkImportResult>("/api/dns-blocks/import", {
      method: "POST",
      body,
    }),
};
