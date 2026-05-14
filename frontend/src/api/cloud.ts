import { api } from "./client";
import type { CloudSource, CloudSourceCreate, CloudSourceUpdate } from "@/types/api";

export const cloudApi = {
  list: () => api<CloudSource[]>("/api/cloud-sources"),
  create: (body: CloudSourceCreate) =>
    api<CloudSource>("/api/cloud-sources", { method: "POST", body }),
  update: (id: string, body: CloudSourceUpdate) =>
    api<CloudSource>(`/api/cloud-sources/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/cloud-sources/${id}`, { method: "DELETE" }),
};
