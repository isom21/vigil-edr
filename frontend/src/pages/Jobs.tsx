/**
 * Jobs engine — fleet-wide job list (M23.i).
 *
 * Each row aggregates a fan-out (one Job → many JobRuns), so the
 * counts column shows completed / failed against the total run set.
 * Click a row to open the detail page with per-host runs + artifacts.
 */
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { ApiError } from "@/api/client";
import { jobsApi } from "@/api/jobs";
import { DataTable, FilterBar } from "@/components/data-table";
import type { ColumnDef, FilterDef } from "@/components/data-table";
import { JobCreateModal } from "@/components/JobCreateModal";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { useTableQuery } from "@/hooks/useTableQuery";
import { useColumnFilters } from "@/lib/table-filters";
import { cn } from "@/lib/utils";
import type { Job, JobKind, JobStatus } from "@/types/api";

const STATUSES: JobStatus[] = ["queued", "running", "completed", "failed", "canceled"];
const KINDS: JobKind[] = [
  "host_sweep",
  "process_snapshot",
  "network_snapshot",
  "installed_software",
  "persistence_audit",
  "service_audit",
  "account_audit",
  "yara_fs_scan",
  "ioc_sweep",
  "hash_files",
  "file_acquire",
  "crash_dump_collect",
  "event_log_acquire",
  "triage_collect",
  "agent_diagnostic",
  "shell_command",
  "kill_process",
  "delete_file",
  "isolate",
  "unisolate",
  "quarantine_file",
  "release_quarantine",
];

const FILTERS: FilterDef[] = [
  {
    key: "status",
    label: "status",
    options: STATUSES.map((s) => ({ value: s, label: s })),
  },
  {
    key: "kind",
    label: "kind",
    options: KINDS.map((k) => ({ value: k, label: k })),
  },
  {
    // Deep-link target from AlertDetailPanel's "Tracked in Jobs →".
    // No dropdown — the URL carries the value.
    key: "triggered_by_alert_id",
    label: "alert",
    options: [],
    hidden: true,
    formatValue: (v) => v.slice(0, 8),
  },
];

const STATUS_CLASS: Record<JobStatus, string> = {
  queued: "bg-muted text-muted-foreground border-border",
  running: "bg-sev-low/15 text-sev-low border-sev-low/30",
  completed: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  failed: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  canceled: "bg-amber-500/15 text-amber-500 border-amber-500/30",
};

function asStatus(v: string | undefined): JobStatus | undefined {
  return v && (STATUSES as string[]).includes(v) ? (v as JobStatus) : undefined;
}
function asKind(v: string | undefined): JobKind | undefined {
  return v && (KINDS as string[]).includes(v) ? (v as JobKind) : undefined;
}

export function Jobs() {
  const navigate = useNavigate();
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();
  const { state, setFilter, clearFilters, setSort, setOffset, setLimit, setHiddenCols } =
    useTableQuery({ limit: 50 });
  const [createOpen, setCreateOpen] = useState(false);

  const filters = state.filters;
  const statusFilter = asStatus(filters.status);
  const kindFilter = asKind(filters.kind);
  const triggeredByAlertId = filters.triggered_by_alert_id || undefined;

  const list = useQuery({
    queryKey: ["jobs", { ...filters, offset: state.offset, limit: state.limit }],
    queryFn: () =>
      jobsApi.list({
        status_: statusFilter,
        kind: kindFilter,
        triggered_by_alert_id: triggeredByAlertId,
        limit: state.limit,
        offset: state.offset,
      }),
    refetchInterval: 5000,
    placeholderData: (prev) => prev,
  });

  const columns: ColumnDef<Job>[] = useMemo(
    () => [
      {
        id: "created_at",
        header: "Created",
        sortable: true,
        filterValue: (j) => j.created_at,
        cell: (j) => (
          <time
            dateTime={j.created_at}
            className="font-mono text-xs tabular-nums"
            title={j.created_at}
          >
            {new Date(j.created_at).toLocaleString()}
          </time>
        ),
      },
      {
        id: "kind",
        header: "Kind",
        sortable: true,
        filterValue: (j) => j.kind,
        cell: (j) => (
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {j.kind}
          </span>
        ),
      },
      {
        id: "summary",
        header: "Summary",
        filterValue: (j) => j.summary,
        cell: (j) => <span className="block max-w-md truncate text-sm">{j.summary}</span>,
      },
      {
        id: "scope",
        header: "Scope",
        filterValue: (j) => j.scope_kind,
        cell: (j) => (
          <span className="font-mono text-xs uppercase text-muted-foreground">
            {j.scope_kind === "host_ids" ? `${j.scope_host_ids?.length ?? 0} hosts` : j.scope_kind}
          </span>
        ),
      },
      {
        id: "runs",
        header: "Runs",
        filterValue: (j) => j.run_count,
        cell: (j) => (
          <span className="font-mono text-xs tabular-nums">
            <span className="text-emerald-500">{j.run_completed}</span>
            <span className="text-muted-foreground">/</span>
            <span className="text-sev-critical">{j.run_failed}</span>
            <span className="text-muted-foreground">/</span>
            <span>{j.run_count}</span>
          </span>
        ),
      },
      {
        id: "status",
        header: "Status",
        sortable: true,
        filterValue: (j) => j.status,
        cell: (j) => (
          <span
            className={cn(
              "inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider",
              STATUS_CLASS[j.status],
            )}
          >
            {j.status}
          </span>
        ),
      },
      {
        id: "trigger",
        header: "Trigger",
        filterValue: (j) => j.triggered_by,
        cell: (j) => (
          <span className="font-mono text-xs text-muted-foreground">{j.triggered_by}</span>
        ),
        hiddenByDefault: true,
      },
      {
        id: "id",
        header: "ID",
        hiddenByDefault: true,
        filterValue: (j) => j.id,
        cell: (j) => (
          <Link
            to={`/jobs/${j.id}`}
            onClick={(e) => e.stopPropagation()}
            className="font-mono text-xs underline-offset-2 hover:underline"
          >
            {j.id.slice(0, 8)}
          </Link>
        ),
      },
    ],
    [],
  );

  return (
    <>
      <PageHeader
        title="Jobs"
        description={`${list.data?.total ?? 0} jobs across visible hosts`}
        actions={
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="h-3.5 w-3.5" aria-hidden="true" /> New job
          </Button>
        }
      />
      <div className="space-y-4 px-8 py-6">
        <DataTable<Job>
          tableId="jobs"
          columns={columns}
          rows={list.data?.items}
          total={list.data?.total ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No jobs match the current filters."
          getRowId={(j) => j.id}
          onRowClick={(j) => navigate(`/jobs/${j.id}`)}
          sort={state.sort}
          onSortChange={setSort}
          offset={state.offset}
          limit={state.limit}
          onOffsetChange={setOffset}
          onLimitChange={setLimit}
          hiddenCols={state.hiddenCols}
          onHiddenColsChange={setHiddenCols}
          columnFilters={columnFilters}
          onColumnFiltersChange={setColumnFilters}
          savedFiltersTableId="jobs"
          toolbar={
            <FilterBar
              filters={FILTERS}
              values={filters}
              onFilterChange={setFilter}
              onClearAll={clearFilters}
            />
          }
        />
      </div>
      {createOpen && (
        <JobCreateModal
          onClose={() => setCreateOpen(false)}
          onCreated={(jobId) => {
            setCreateOpen(false);
            navigate(`/jobs/${jobId}`);
          }}
        />
      )}
    </>
  );
}
