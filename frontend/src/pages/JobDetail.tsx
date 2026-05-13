/**
 * Job detail page (M23.i).
 *
 * Shows the job header (kind / scope / status / aggregate counts) plus
 * a table of JobRun rows (one per host). Selecting a run reveals its
 * artifact list with download buttons that hit the manager's presigned-
 * URL endpoint and forward the browser to MinIO.
 */
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, FileText, X } from "lucide-react";
import { ApiError } from "@/api/client";
import { jobsApi } from "@/api/jobs";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type {
  Job,
  JobArtifact,
  JobArtifactKind,
  JobRun,
  JobRunStatus,
  JobStatus,
} from "@/types/api";

const RUN_STATUS_CLASS: Record<JobRunStatus, string> = {
  queued: "bg-muted text-muted-foreground border-border",
  dispatched: "bg-muted text-muted-foreground border-border",
  running: "bg-sev-low/15 text-sev-low border-sev-low/30",
  completed: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  failed: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  canceled: "bg-amber-500/15 text-amber-500 border-amber-500/30",
  timeout: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
};

const JOB_STATUS_CLASS: Record<JobStatus, string> = {
  queued: "bg-muted text-muted-foreground border-border",
  running: "bg-sev-low/15 text-sev-low border-sev-low/30",
  completed: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  failed: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  canceled: "bg-amber-500/15 text-amber-500 border-amber-500/30",
};

const ARTIFACT_KIND_LABEL: Record<JobArtifactKind, string> = {
  json: "JSON",
  file: "File",
  yara_matches: "YARA matches",
  ioc_matches: "IOC matches",
  hash_list: "Hashes",
  shell_output: "Shell output",
  diagnostic_bundle: "Diagnostic",
};

export function JobDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);

  const detail = useQuery({
    queryKey: ["job", id],
    queryFn: () => jobsApi.get(id!),
    enabled: !!id,
    // Poll while the job is in a non-terminal state — once it settles
    // the refetch loop stops.
    refetchInterval: (q) => {
      const data = q.state.data as Job | undefined;
      const inflight = !data || data.status === "queued" || data.status === "running";
      return inflight ? 2000 : false;
    },
  });

  const cancel = useMutation({
    mutationFn: () => jobsApi.cancel(id!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["job", id] }),
  });

  if (!id) return null;
  if (detail.isLoading) return <p className="p-8 text-sm">Loading…</p>;
  if (detail.isError) {
    const msg = detail.error instanceof ApiError ? detail.error.detail : "Failed to load.";
    return <p className="p-8 text-sm text-destructive">{msg}</p>;
  }
  const job = detail.data;
  if (!job) return <p className="p-8 text-sm">Not found.</p>;

  const selectedRun = job.runs.find((r) => r.id === selectedRunId) ?? null;
  const cancelable =
    job.status !== "completed" && job.status !== "failed" && job.status !== "canceled";

  return (
    <>
      <PageHeader
        title={`Job · ${job.kind}`}
        description={
          <span className="inline-flex items-center gap-3">
            <Link
              to="/jobs"
              className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" /> all jobs
            </Link>
            <span className="text-muted-foreground/40">·</span>
            <span className="font-mono text-xs text-muted-foreground" title={job.id}>
              {job.id.slice(0, 8)}
            </span>
            <span className="text-muted-foreground/40">·</span>
            <span>{job.summary}</span>
          </span>
        }
        actions={
          <div className="flex gap-2">
            {cancelable && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => cancel.mutate()}
                disabled={cancel.isPending}
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
                {cancel.isPending ? "Canceling…" : "Cancel"}
              </Button>
            )}
            <Button size="sm" variant="outline" onClick={() => navigate("/jobs")}>
              Back
            </Button>
          </div>
        }
      />
      {job.kind === "triage_collect" && (
        <div className="border-b bg-amber-500/10 px-8 py-2 text-xs text-amber-700 dark:text-amber-300">
          Triage bundle aggregates registry hives, browser history, event logs and other
          secrets-bearing artifacts into a single ZIP. Handle the downloaded archive on an isolated
          analyst workstation.
        </div>
      )}
      <div className="grid gap-4 px-8 py-6 lg:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Job</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 pt-0 text-xs">
            <Row label="kind">{job.kind}</Row>
            <Row label="scope">
              {job.scope_kind === "host_ids"
                ? `${job.scope_host_ids?.length ?? 0} host(s)`
                : job.scope_kind}
            </Row>
            <Row label="status">
              <span
                className={cn(
                  "inline-flex rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider",
                  JOB_STATUS_CLASS[job.status],
                )}
              >
                {job.status}
              </span>
            </Row>
            <Row label="trigger">
              <span className="font-mono">{job.triggered_by}</span>
            </Row>
            <Row label="created">
              <time
                dateTime={job.created_at}
                className="font-mono tabular-nums"
                title={job.created_at}
              >
                {new Date(job.created_at).toLocaleString()}
              </time>
            </Row>
            <Row label="runs">
              <span className="font-mono tabular-nums">
                <span className="text-emerald-500">{job.run_completed}</span>
                <span className="text-muted-foreground">/</span>
                <span className="text-sev-critical">{job.run_failed}</span>
                <span className="text-muted-foreground">/</span>
                <span>{job.run_count}</span>
              </span>
            </Row>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Parameters</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            {Object.keys(job.parameters).length === 0 ? (
              <p className="text-xs text-muted-foreground">No parameters.</p>
            ) : (
              <pre className="overflow-auto rounded-sm border bg-muted/30 p-3 text-xs">
                {JSON.stringify(job.parameters, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">
              Runs <span className="ml-2 text-xs text-muted-foreground">{job.runs.length}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <table className="w-full text-xs">
              <thead className="bg-card text-left text-muted-foreground">
                <tr className="border-b">
                  <th className="px-3 py-2 font-medium">Host</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Progress</th>
                  <th className="px-3 py-2 font-medium">Started</th>
                  <th className="px-3 py-2 font-medium">Completed</th>
                  <th className="px-3 py-2 font-medium">Artifacts</th>
                </tr>
              </thead>
              <tbody>
                {job.runs.map((run) => {
                  const isSelected = run.id === selectedRunId;
                  return (
                    <tr
                      key={run.id}
                      onClick={() => setSelectedRunId(isSelected ? null : run.id)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setSelectedRunId(isSelected ? null : run.id);
                        }
                      }}
                      tabIndex={0}
                      role="button"
                      aria-pressed={isSelected}
                      className={cn(
                        "cursor-pointer border-b border-border/40 align-top hover:bg-secondary/30 focus-visible:bg-secondary/40 focus-visible:outline-none",
                        isSelected && "bg-secondary/40",
                      )}
                    >
                      <td className="px-3 py-1.5 text-sm">
                        <Link
                          to={`/hosts/${run.host_id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="block max-w-xs truncate underline-offset-2 hover:underline"
                        >
                          {run.host_hostname ?? (
                            <span className="font-mono text-xs">{run.host_id.slice(0, 8)}…</span>
                          )}
                        </Link>
                      </td>
                      <td className="px-3 py-1.5">
                        <span
                          className={cn(
                            "inline-flex rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider",
                            RUN_STATUS_CLASS[run.status],
                          )}
                        >
                          {run.status}
                        </span>
                      </td>
                      <td className="px-3 py-1.5">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
                            <div
                              className="h-full bg-sev-low"
                              style={{ width: `${run.progress_pct}%` }}
                            />
                          </div>
                          <span className="font-mono tabular-nums text-muted-foreground">
                            {run.progress_pct}%
                          </span>
                        </div>
                        {run.progress_message && (
                          <p
                            className="mt-0.5 truncate text-[11px] text-muted-foreground"
                            title={run.progress_message}
                          >
                            {run.progress_message}
                          </p>
                        )}
                      </td>
                      <td className="px-3 py-1.5 font-mono tabular-nums text-muted-foreground">
                        {run.started_at ? new Date(run.started_at).toLocaleTimeString() : "—"}
                      </td>
                      <td className="px-3 py-1.5 font-mono tabular-nums text-muted-foreground">
                        {run.completed_at ? new Date(run.completed_at).toLocaleTimeString() : "—"}
                      </td>
                      <td className="px-3 py-1.5 font-mono tabular-nums">{run.artifact_count}</td>
                    </tr>
                  );
                })}
                {job.runs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-3 py-6 text-center text-muted-foreground">
                      No runs yet — agent may not have picked up the command.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </CardContent>
        </Card>

        {selectedRun && (
          <ArtifactsCard jobId={job.id} run={selectedRun} onClose={() => setSelectedRunId(null)} />
        )}
      </div>
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium">{children}</span>
    </div>
  );
}

function ArtifactsCard({
  jobId,
  run,
  onClose,
}: {
  jobId: string;
  run: JobRun;
  onClose: () => void;
}) {
  const list = useQuery({
    queryKey: ["job-artifacts", jobId, run.id],
    queryFn: () => jobsApi.listArtifacts(jobId, run.id),
  });

  return (
    <Card className="lg:col-span-3">
      <CardHeader className="flex-row items-center justify-between pb-2">
        <CardTitle className="text-base">
          Artifacts — {run.host_hostname ?? run.host_id.slice(0, 8)}
        </CardTitle>
        <Button size="sm" variant="outline" onClick={onClose}>
          <X className="h-3.5 w-3.5" aria-hidden="true" /> close
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {list.isLoading && <p className="px-4 py-3 text-xs">Loading…</p>}
        {list.isError && (
          <p className="px-4 py-3 text-xs text-destructive">
            {list.error instanceof ApiError ? list.error.detail : "Failed to load."}
          </p>
        )}
        {list.data && list.data.length === 0 && (
          <p className="px-4 py-3 text-xs text-muted-foreground">
            No artifacts uploaded for this run.
          </p>
        )}
        {list.data && list.data.length > 0 && (
          <table className="w-full text-xs">
            <thead className="bg-card text-left text-muted-foreground">
              <tr className="border-b">
                <th className="px-3 py-2 font-medium">Kind</th>
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium">Size</th>
                <th className="px-3 py-2 font-medium">SHA-256</th>
                <th className="px-3 py-2 font-medium">Created</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((a) => (
                <ArtifactRow key={a.id} artifact={a} />
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );
}

function ArtifactRow({ artifact }: { artifact: JobArtifact }) {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    setDownloading(true);
    setError(null);
    try {
      const res = await jobsApi.downloadArtifact(artifact.id);
      window.location.href = res.url;
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setDownloading(false);
    }
  }

  const filename = artifact.object_key.split("/").pop() ?? artifact.object_key;
  return (
    <tr className="border-b border-border/40">
      <td className="px-3 py-1.5">
        <span className="inline-flex items-center gap-1 font-mono text-xs">
          <FileText className="h-3 w-3" aria-hidden="true" />
          {ARTIFACT_KIND_LABEL[artifact.kind]}
        </span>
      </td>
      <td className="px-3 py-1.5 font-mono text-xs">{filename}</td>
      <td className="px-3 py-1.5 font-mono tabular-nums text-muted-foreground">
        {artifact.size_bytes.toLocaleString()}
      </td>
      <td className="px-3 py-1.5 font-mono text-muted-foreground" title={artifact.sha256 ?? ""}>
        {artifact.sha256 ? `${artifact.sha256.slice(0, 12)}…` : "—"}
      </td>
      <td className="px-3 py-1.5 font-mono tabular-nums text-muted-foreground">
        {new Date(artifact.created_at).toLocaleString()}
      </td>
      <td className="px-3 py-1.5 text-right">
        <Button size="sm" variant="outline" onClick={download} disabled={downloading}>
          <Download className="h-3.5 w-3.5" aria-hidden="true" />
          {downloading ? "Linking…" : "Download"}
        </Button>
        {error && <p className="mt-1 text-[11px] text-destructive">{error}</p>}
      </td>
    </tr>
  );
}
