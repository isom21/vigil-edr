import { api } from "./client";
import type { DevicePolicy, DevicePolicyCreate, DevicePolicyUpdate } from "@/types/api";

export const deviceControlApi = {
  list: (params?: { host_group_id?: string }) =>
    api<DevicePolicy[]>("/api/device-policies", { query: params }),
  create: (body: DevicePolicyCreate) =>
    api<DevicePolicy>("/api/device-policies", { method: "POST", body }),
  update: (id: string, body: DevicePolicyUpdate) =>
    api<DevicePolicy>(`/api/device-policies/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/device-policies/${id}`, { method: "DELETE" }),
};
