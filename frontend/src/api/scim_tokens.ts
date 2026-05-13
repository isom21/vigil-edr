/**
 * Admin client for SCIM bearer tokens (Phase 3 #3.8).
 *
 * The raw token is returned exactly once on create — `ScimTokenCreated`
 * extends `ScimToken` with a `token` field that's never present in the
 * list view.
 */
import type { ScimToken, ScimTokenCreated } from "@/types/api";
import { api } from "./client";

export const scimTokensApi = {
  list: () => api<ScimToken[]>("/api/scim-tokens"),
  create: (body: { label: string }) =>
    api<ScimTokenCreated>("/api/scim-tokens", { method: "POST", body }),
  disable: (id: string) => api<void>(`/api/scim-tokens/${id}/disable`, { method: "POST" }),
  remove: (id: string) => api<void>(`/api/scim-tokens/${id}`, { method: "DELETE" }),
};
