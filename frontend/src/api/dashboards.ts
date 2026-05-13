/**
 * Operator-authored dashboards (Phase 3 #3.4).
 *
 * The default-dashboard endpoint is the one the overview page hits on
 * every load — when a user lands on `/dashboard` for the first time
 * the server auto-creates a sensible default and returns it. All
 * other endpoints follow the CRUD shape.
 */
import { api } from "./client";
import type { Dashboard, DashboardCreate, DashboardUpdate, WidgetData } from "@/types/api";

export const dashboardsApi = {
  list: () => api<Dashboard[]>("/api/dashboards"),
  getDefault: () => api<Dashboard>("/api/dashboards/default"),
  get: (id: string) => api<Dashboard>(`/api/dashboards/${id}`),
  create: (body: DashboardCreate) => api<Dashboard>("/api/dashboards", { method: "POST", body }),
  update: (id: string, body: DashboardUpdate) =>
    api<Dashboard>(`/api/dashboards/${id}`, { method: "PUT", body }),
  remove: (id: string) => api<void>(`/api/dashboards/${id}`, { method: "DELETE" }),
  duplicate: (id: string) => api<Dashboard>(`/api/dashboards/${id}/duplicate`, { method: "POST" }),
  data: (id: string) => api<WidgetData[]>(`/api/dashboards/${id}/data`),
};
