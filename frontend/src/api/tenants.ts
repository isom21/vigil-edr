import { api } from "./client";
import type { Tenant, TenantCreate, TenantUpdate } from "@/types/api";

// Phase 3 #3.1: tenant CRUD. All super-admin only at the API level;
// the UI hides the routes for non-super-admins so the call sites
// themselves stay simple.
export const tenantsApi = {
  list: () => api<Tenant[]>("/api/tenants"),
  get: (id: string) => api<Tenant>(`/api/tenants/${id}`),
  create: (body: TenantCreate) => api<Tenant>("/api/tenants", { method: "POST", body }),
  update: (id: string, body: TenantUpdate) =>
    api<Tenant>(`/api/tenants/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/tenants/${id}`, { method: "DELETE" }),
};
