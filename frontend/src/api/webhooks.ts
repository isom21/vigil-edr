import { api } from "./client";
import type {
  WebhookDeliveryPage,
  WebhookEventType,
  WebhookSubscription,
  WebhookSubscriptionCreate,
  WebhookSubscriptionCreateResponse,
  WebhookSubscriptionUpdate,
} from "@/types/api";

export const webhooksApi = {
  list: () => api<WebhookSubscription[]>("/api/webhooks"),
  get: (id: string) => api<WebhookSubscription>(`/api/webhooks/${id}`),
  create: (body: WebhookSubscriptionCreate) =>
    api<WebhookSubscriptionCreateResponse>("/api/webhooks", { method: "POST", body }),
  update: (id: string, body: WebhookSubscriptionUpdate) =>
    api<WebhookSubscription>(`/api/webhooks/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/webhooks/${id}`, { method: "DELETE" }),
  rotate: (id: string) =>
    api<WebhookSubscriptionCreateResponse>(`/api/webhooks/${id}/rotate`, { method: "POST" }),
  test: (id: string, event_type: WebhookEventType) =>
    api<{
      id: string;
      status: string;
      attempts: number;
      response_status: number | null;
      response_body_truncated: string | null;
    }>(`/api/webhooks/${id}/test`, {
      method: "POST",
      body: { event_type },
    }),
  deliveries: (id: string, limit = 50, offset = 0) =>
    api<WebhookDeliveryPage>(`/api/webhooks/${id}/deliveries`, {
      query: { limit, offset },
    }),
};
