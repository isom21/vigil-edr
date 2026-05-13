/**
 * Phase 3 #3.2: OpenSearch ILM + S3 cold archive.
 *
 * Renders the manager's archive_job ledger. Daily worker freezes
 * cold-tier OpenSearch indices to MinIO as `.ndjson.zst` blobs;
 * operators rehydrate on demand when an investigation needs older
 * data than what's currently hot in the cluster.
 *
 * Frozen indices are listed front-and-centre. In-flight and failed
 * jobs surface in a secondary "Job history" card so a stuck freeze is
 * visible without scrolling through the success log.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Archive as ArchiveIcon, AlertCircle, Clock, RefreshCw } from "lucide-react";

import { archiveApi } from "@/api/archive";
import { ApiError } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/hooks/useAuth";
import type { ArchiveJob, ArchiveJobStatus } from "@/types/api";

const STATUS_VARIANT: Record<
  ArchiveJobStatus,
  "default" | "secondary" | "destructive" | "outline"
> = {
  pending: "outline",
  freezing: "secondary",
  frozen: "default",
  rehydrating: "secondary",
  rehydrated: "default",
  failed: "destructive",
};

function fmtBytes(_: ArchiveJob): string {
  // Doc count is the most operator-meaningful size signal we record;
  // we don't persist compressed byte size today. Render as "—" when
  // missing so the column stays aligned.
  return "—";
}

function fmtTimestamp(t: string | null | undefined): string {
  if (!t) return "—";
  return new Date(t).toLocaleString();
}

export function Archive() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const qc = useQueryClient();

  const frozen = useQuery({
    queryKey: ["archive-frozen"],
    queryFn: () => archiveApi.listFrozen({ limit: 200 }),
    refetchInterval: 30_000,
  });

  const allJobs = useQuery({
    queryKey: ["archive-jobs"],
    queryFn: () => archiveApi.listJobs({ limit: 200 }),
    refetchInterval: 10_000,
  });

  const rehydrate = useMutation({
    mutationFn: (id: string) => archiveApi.rehydrate(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["archive-frozen"] });
      qc.invalidateQueries({ queryKey: ["archive-jobs"] });
    },
  });

  // Surface the most recent in-flight / failed rows separately so
  // operators see them without scrolling past the frozen ledger.
  const inFlight = (allJobs.data ?? []).filter(
    (j) => j.status === "freezing" || j.status === "rehydrating" || j.status === "pending",
  );
  const failed = (allJobs.data ?? []).filter((j) => j.status === "failed");

  return (
    <>
      <PageHeader
        title="Cold archive"
        description={
          <span>
            OpenSearch indices past the cold-tier age are frozen to MinIO as compressed NDJSON. Use{" "}
            <strong>Rehydrate</strong> to bring an index back online for investigation — the
            rehydrated data is queryable under the original index name via a temporary alias.
          </span>
        }
      />
      <div className="space-y-6 p-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ArchiveIcon className="h-4 w-4" aria-hidden="true" />
              Frozen indices ({frozen.data?.length ?? 0})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Index</TableHead>
                  <TableHead>Frozen at</TableHead>
                  <TableHead className="text-right">Docs</TableHead>
                  <TableHead>S3 key</TableHead>
                  {isAdmin && <TableHead className="text-right">Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {frozen.isLoading && (
                  <TableRow>
                    <TableCell colSpan={isAdmin ? 5 : 4} className="text-muted-foreground">
                      Loading…
                    </TableCell>
                  </TableRow>
                )}
                {!frozen.isLoading && (frozen.data?.length ?? 0) === 0 && (
                  <TableRow>
                    <TableCell colSpan={isAdmin ? 5 : 4} className="text-muted-foreground">
                      No frozen indices yet. The archive worker freezes indices once they cross the
                      cold-tier age (default 90 days).
                    </TableCell>
                  </TableRow>
                )}
                {frozen.data?.map((j) => (
                  <FrozenRow
                    key={j.id}
                    job={j}
                    isAdmin={isAdmin}
                    onRehydrate={() => rehydrate.mutate(j.id)}
                    pending={rehydrate.isPending && rehydrate.variables === j.id}
                    error={
                      rehydrate.isError && rehydrate.variables === j.id
                        ? rehydrate.error instanceof ApiError
                          ? rehydrate.error.detail
                          : String(rehydrate.error)
                        : null
                    }
                  />
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {(inFlight.length > 0 || failed.length > 0) && (
          <Card>
            <CardHeader>
              <CardTitle>Job history</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Index</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Finished</TableHead>
                    <TableHead>Error</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {[...inFlight, ...failed].map((j) => (
                    <TableRow key={j.id}>
                      <TableCell className="font-mono text-xs">{j.index_name}</TableCell>
                      <TableCell>
                        <StatusBadge status={j.status} />
                      </TableCell>
                      <TableCell className="text-xs tabular-nums text-muted-foreground">
                        {fmtTimestamp(j.started_at)}
                      </TableCell>
                      <TableCell className="text-xs tabular-nums text-muted-foreground">
                        {fmtTimestamp(j.finished_at)}
                      </TableCell>
                      <TableCell
                        className="max-w-md truncate text-xs text-destructive"
                        title={j.error ?? undefined}
                      >
                        {j.error ?? "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </div>
    </>
  );
}

function FrozenRow({
  job,
  isAdmin,
  onRehydrate,
  pending,
  error,
}: {
  job: ArchiveJob;
  isAdmin: boolean;
  onRehydrate: () => void;
  pending: boolean;
  error: string | null;
}) {
  return (
    <TableRow>
      <TableCell className="font-mono text-xs">{job.index_name}</TableCell>
      <TableCell className="text-xs tabular-nums text-muted-foreground">
        {fmtTimestamp(job.finished_at ?? job.created_at)}
      </TableCell>
      <TableCell className="text-right text-xs tabular-nums">
        {job.doc_count != null ? job.doc_count.toLocaleString() : fmtBytes(job)}
      </TableCell>
      <TableCell
        className="max-w-md truncate font-mono text-[11px] text-muted-foreground"
        title={job.s3_key ?? undefined}
      >
        {job.s3_key ?? "—"}
      </TableCell>
      {isAdmin && (
        <TableCell className="text-right">
          <div className="flex flex-col items-end gap-1">
            <Button size="sm" variant="ghost" onClick={onRehydrate} disabled={pending}>
              <RefreshCw
                className={`mr-1 h-3.5 w-3.5${pending ? " animate-spin" : ""}`}
                aria-hidden="true"
              />
              Rehydrate
            </Button>
            {error && <span className="text-[11px] text-destructive">{error}</span>}
          </div>
        </TableCell>
      )}
    </TableRow>
  );
}

function StatusBadge({ status }: { status: ArchiveJobStatus }) {
  const variant = STATUS_VARIANT[status] ?? "outline";
  const Icon = status === "failed" ? AlertCircle : Clock;
  return (
    <Badge variant={variant} className="gap-1 text-xs">
      <Icon className="h-3 w-3" aria-hidden="true" />
      {status}
    </Badge>
  );
}
