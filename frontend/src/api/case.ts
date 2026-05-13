import { api } from "./client";
import type {
  CaseDestination,
  CaseDestinationCreate,
  CaseDestinationTestResult,
  CaseDestinationUpdate,
} from "@/types/api";

export const caseApi = {
  list: () => api<CaseDestination[]>("/api/case-destinations"),
  create: (body: CaseDestinationCreate) =>
    api<CaseDestination>("/api/case-destinations", { method: "POST", body }),
  update: (id: string, body: CaseDestinationUpdate) =>
    api<CaseDestination>(`/api/case-destinations/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/case-destinations/${id}`, { method: "DELETE" }),
  test: (id: string) =>
    api<CaseDestinationTestResult>(`/api/case-destinations/${id}/test`, { method: "POST" }),
};
