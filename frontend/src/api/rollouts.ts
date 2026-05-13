import { api } from "./client";
import type { PolicyRolloutOut } from "@/types/api";

export const rolloutsApi = {
  list: () => api<PolicyRolloutOut[]>("/api/rollouts"),
  advance: (policyId: string, toPct: number) =>
    api<PolicyRolloutOut>(`/api/rollouts/${policyId}/advance`, {
      method: "POST",
      body: { to_pct: toPct },
    }),
};
