import { api } from "./client";
import type {
  ArtifactDownload,
  Job,
  JobArtifact,
  JobCreateBody,
  JobDetail,
  JobKind,
  JobRun,
  JobStatus,
  Page,
} from "@/types/api";

export interface JobListParams {
  kind?: JobKind;
  status_?: JobStatus;
  triggered_by_alert_id?: string;
  limit?: number;
  offset?: number;
}

export const jobsApi = {
  list: (params: JobListParams = {}) =>
    api<Page<Job>>("/api/jobs", { query: params as Record<string, string | number> }),

  create: (body: JobCreateBody) => api<JobDetail>("/api/jobs", { method: "POST", body }),

  get: (id: string) => api<JobDetail>(`/api/jobs/${id}`),

  listRuns: (id: string, params: { status_?: string; limit?: number; offset?: number } = {}) =>
    api<Page<JobRun>>(`/api/jobs/${id}/runs`, {
      query: params as Record<string, string | number>,
    }),

  listArtifacts: (id: string, runId: string) =>
    api<JobArtifact[]>(`/api/jobs/${id}/runs/${runId}/artifacts`),

  cancel: (id: string) => api<JobDetail>(`/api/jobs/${id}/cancel`, { method: "POST" }),

  downloadArtifact: (artifactId: string) =>
    api<ArtifactDownload>(`/api/artifacts/${artifactId}/download`),
};
