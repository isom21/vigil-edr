import { api } from "./client";
import type { AlertSummary, NlQueryRequest, NlQueryResponse } from "@/types/api";

export const aiApi = {
  // 404 is the "not ready yet" signal; the AlertDetail widget renders a
  // pending spinner on that case instead of an error card. We don't
  // suppress the error here — let the React Query layer expose it so
  // the widget can branch on it explicitly.
  getAlertSummary: (alertId: string) => api<AlertSummary>(`/api/alerts/${alertId}/summary`),

  nlToQuery: (body: NlQueryRequest) =>
    api<NlQueryResponse>("/api/ai/nl-to-query", { method: "POST", body }),
};
