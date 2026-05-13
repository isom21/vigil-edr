import { api } from "./client";
import type {
  AllowlistEntry,
  AllowlistEntryCreate,
  AllowlistMode,
  AllowlistModeOut,
} from "@/types/api";

export const allowlistApi = {
  getMode: (groupId: string) => api<AllowlistModeOut>(`/api/host-groups/${groupId}/allowlist`),
  setMode: (groupId: string, mode: AllowlistMode) =>
    api<AllowlistModeOut>(`/api/host-groups/${groupId}/allowlist/mode`, {
      method: "PUT",
      body: { mode },
    }),
  listEntries: (groupId: string) =>
    api<AllowlistEntry[]>(`/api/host-groups/${groupId}/allowlist/entries`),
  createEntry: (groupId: string, body: AllowlistEntryCreate) =>
    api<AllowlistEntry>(`/api/host-groups/${groupId}/allowlist/entries`, {
      method: "POST",
      body,
    }),
  deleteEntry: (groupId: string, entryId: string) =>
    api<void>(`/api/host-groups/${groupId}/allowlist/entries/${entryId}`, {
      method: "DELETE",
    }),
};
