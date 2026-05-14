/**
 * Phase 4 #4.3 — identity threat detection source CRUD client.
 *
 * Admin-only endpoints. The encrypted config is never returned by the
 * API, so the list/get shapes only carry metadata; the create/update
 * payloads accept a plain `config` object that the backend Fernet-
 * encrypts at rest.
 */
import { api } from "./client";
import type { IdentitySource, IdentitySourceCreate, IdentitySourceUpdate } from "@/types/api";

export const identityApi = {
  list: () => api<IdentitySource[]>("/api/identity-sources"),
  get: (id: string) => api<IdentitySource>(`/api/identity-sources/${id}`),
  create: (body: IdentitySourceCreate) =>
    api<IdentitySource>("/api/identity-sources", { method: "POST", body }),
  update: (id: string, body: IdentitySourceUpdate) =>
    api<IdentitySource>(`/api/identity-sources/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/identity-sources/${id}`, { method: "DELETE" }),
};
