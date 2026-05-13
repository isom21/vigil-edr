import { api } from "./client";
import type { NotificationChannel, NotificationChannelKind } from "@/types/api";

export interface NotificationChannelCreateBody {
  name: string;
  kind: NotificationChannelKind;
  config: Record<string, unknown>;
  enabled?: boolean;
}

export interface NotificationChannelUpdateBody {
  name?: string;
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export const notificationsApi = {
  list: () => api<NotificationChannel[]>("/api/notifications/channels"),
  get: (id: string) => api<NotificationChannel>(`/api/notifications/channels/${id}`),
  create: (body: NotificationChannelCreateBody) =>
    api<NotificationChannel>("/api/notifications/channels", {
      method: "POST",
      body,
    }),
  update: (id: string, body: NotificationChannelUpdateBody) =>
    api<NotificationChannel>(`/api/notifications/channels/${id}`, {
      method: "PATCH",
      body,
    }),
  remove: (id: string) => api<void>(`/api/notifications/channels/${id}`, { method: "DELETE" }),
};
