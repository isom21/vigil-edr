import { useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { commandsApi } from "@/api/commands";
import { ApiError } from "@/api/client";
import { CommandStatusBadge } from "@/components/badges";
import { BarChart, ChartCard, DonutChart } from "@/components/charts";
import { DataTable, FilterBar } from "@/components/data-table";
import type { ColumnDef, FilterDef } from "@/components/data-table";
import { PageHeader } from "@/components/PageHeader";
import { useTableQuery } from "@/hooks/useTableQuery";
import type { CommandKind, CommandStatus, StatBucket } from "@/types/api";

const STATUSES: CommandStatus[] = ["pending", "dispatched", "succeeded", "failed"];
const KINDS: CommandKind[] = [
  "kill_process",
  "block_process",
  "block_file",
  "unblock_process",
  "unblock_file",
  "scan_file",
  "scan_memory",
  "isolate",
  "update",
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
];

const STATUS_COLOR: Record<CommandStatus, string> = {
  pending: "hsl(var(--sev-medium))",
  dispatched: "hsl(var(--sev-low))",
  succeeded: "hsl(143 64% 50%)",
  failed: "hsl(var(--sev-critical))",
};

function statusBuckets(data: StatBucket[] | undefined) {
  return STATUSES.map((s) => ({
    key: s,
    label: s,
    color: STATUS_COLOR[s],
    count: data?.find((b) => b.key === s)?.count ?? 0,
  }));
}

function asStatus(v: string | undefined): CommandStatus | undefined {
  return v && (STATUSES as string[]).includes(v) ? (v as CommandStatus) : undefined;
}

function asKind(v: string | undefined): CommandKind | undefined {
  return v && (KINDS as string[]).includes(v) ? (v as CommandKind) : undefined;
}

function payloadSummary(kind: CommandKind, payload: Record<string, unknown>): string {
  if (kind === "kill_process") return `pid=${payload.pid ?? "?"}`;
  if ("pattern" in payload) return String(payload.pattern);
  return JSON.stringify(payload);
}

export function Commands() {
  const navigate = useNavigate();
  const { state, setFilter, clearFilters, setSort, setOffset, setHiddenCols } = useTableQuery({
    limit: 50,
  });

  const filters = state.filters;
  const statusFilter = asStatus(filters.status);
  const kindFilter = asKind(filters.kind);

  const list = useQuery({
    queryKey: [
      "commands",
      { ...filters, sort: state.sort, offset: state.offset, limit: state.limit },
    ],
    queryFn: () =>
      commandsApi.listAll({
        status_: statusFilter,
        kind: kindFilter,
        sort: state.sort ? `${state.sort.id}:${state.sort.desc ? "desc" : "asc"}` : undefined,
        limit: state.limit,
        offset: state.offset,
      }),
    refetchInterval: 5000,
    placeholderData: (prev) => prev,
  });

  const statusStats = useQuery({
    queryKey: ["command-stats", "status"],
    queryFn: () => commandsApi.stats("status"),
  });
  const kindStats = useQuery({
    queryKey: ["command-stats", "kind"],
    queryFn: () => commandsApi.stats("kind"),
  });

  const columns: ColumnDef<{
    id: string;
    host_id: string;
    kind: CommandKind;
    payload: Record<string, unknown>;
    status: CommandStatus;
    error: string | null;
    created_at: string;
    completed_at: string | null;
    dispatched_at: string | null;
  }>[] = useMemo(
    () => [
      {
        id: "created_at",
        header: "Created",
        sortable: true,
        cell: (c) => (
          <span className="font-mono text-xs">{new Date(c.created_at).toLocaleString()}</span>
        ),
      },
      {
        id: "host",
        header: "Host",
        cell: (c) => (
          <span className="font-mono text-xs hover:underline">{c.host_id.slice(0, 8)}…</span>
        ),
      },
      {
        id: "kind",
        header: "Kind",
        sortable: true,
        cell: (c) => (
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {c.kind}
          </span>
        ),
      },
      {
        id: "payload",
        header: "Payload",
        cell: (c) => (
          <span className="block max-w-md truncate font-mono text-xs">
            {payloadSummary(c.kind, c.payload)}
          </span>
        ),
      },
      {
        id: "status",
        header: "Status",
        sortable: true,
        cell: (c) => <CommandStatusBadge status={c.status} />,
      },
      {
        id: "completed_at",
        header: "Completed",
        sortable: true,
        cell: (c) => (
          <span className="text-xs text-muted-foreground">
            {c.completed_at ? new Date(c.completed_at).toLocaleString() : "—"}
          </span>
        ),
      },
      {
        id: "error",
        header: "Error",
        hiddenByDefault: true,
        cell: (c) => (
          <span className="block max-w-xs truncate text-xs text-destructive">{c.error ?? ""}</span>
        ),
      },
      {
        id: "dispatched_at",
        header: "Dispatched",
        sortable: true,
        hiddenByDefault: true,
        cell: (c) => (
          <span className="text-xs text-muted-foreground">
            {c.dispatched_at ? new Date(c.dispatched_at).toLocaleString() : "—"}
          </span>
        ),
      },
      {
        id: "id",
        header: "ID",
        hiddenByDefault: true,
        cell: (c) => <span className="font-mono text-xs">{c.id.slice(0, 8)}</span>,
      },
    ],
    [],
  );

  const defaultHidden = useMemo(
    () => columns.filter((c) => c.hiddenByDefault).map((c) => c.id),
    [columns],
  );

  useEffect(() => {
    if (state.hiddenCols.length === 0 && defaultHidden.length > 0) {
      setHiddenCols(defaultHidden);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <>
      <PageHeader
        title="Commands"
        description={`${list.data?.total ?? 0} response actions across visible hosts`}
      />
      <div className="space-y-6 px-8 py-6">
        <div className="grid gap-4 md:grid-cols-2">
          <ChartCard title="Status">
            <DonutChart
              data={statusBuckets(statusStats.data)}
              size={130}
              activeKey={statusFilter ?? null}
              onSliceClick={(s) => setFilter("status", statusFilter === s.key ? null : s.key)}
            />
          </ChartCard>
          <ChartCard title="Kind">
            <BarChart
              data={(kindStats.data ?? []).map((b) => ({
                key: b.key,
                count: b.count,
              }))}
              activeKey={kindFilter ?? null}
              onBarClick={(b) => setFilter("kind", kindFilter === b.key ? null : b.key)}
            />
          </ChartCard>
        </div>

        <DataTable
          tableId="commands"
          columns={columns}
          rows={list.data?.items}
          total={list.data?.total ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No commands match the current filters."
          getRowId={(c) => c.id}
          onRowClick={(c) => navigate(`/hosts/${c.host_id}`)}
          sort={state.sort}
          onSortChange={setSort}
          offset={state.offset}
          limit={state.limit}
          onOffsetChange={setOffset}
          hiddenCols={state.hiddenCols}
          onHiddenColsChange={setHiddenCols}
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
    </>
  );
}
