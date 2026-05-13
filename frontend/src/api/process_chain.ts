// Phase 2 #2.6: cross-process correlation graph store.
//
// Two surfaces map to the backend's `process_chain` router. The host
// variant lets analysts pivot on a known pid; the alert variant takes
// the trigger pid out of the alert's `details` payload.
import { api } from "./client";
import type { ProcessChainResponse } from "@/types/api";

export const processChainApi = {
  forHost: (hostId: string, pid: number) =>
    api<ProcessChainResponse>(`/api/hosts/${hostId}/process_chain`, {
      query: { pid },
    }),
  forAlert: (alertId: string) => api<ProcessChainResponse>(`/api/alerts/${alertId}/process_chain`),
};
