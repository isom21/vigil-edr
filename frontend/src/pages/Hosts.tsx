import { useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { hostsApi } from "@/api/hosts";
import { ApiError } from "@/api/client";
import { HostStatusBadge } from "@/components/badges";
import { BarChart, ChartCard, DonutChart } from "@/components/charts";
import { DataTable, FilterBar } from "@/components/data-table";
import type { BulkAction, ColumnDef, FilterDef } from "@/components/data-table";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/hooks/useAuth";
import { useTableQuery } from "@/hooks/useTableQuery";
import type { Host, HostStatus, OsFamily, StatBucket } from "@/types/api";

const STATUSES: HostStatus[] = ["pending", "online", "offline", "isolated", "decommissioned"];
const OS: OsFamily[] = ["windows", "linux", "macos"];

const FILTERS: FilterDef[] = [
  {
    key: "status",
    label: "status",
    options: STATUSES.map((s) => ({ value: s, label: s })),
  },
  {
    key: "os_family",
    label: "OS",
    options: OS.map((o) => ({ value: o, label: o })),
  },
];

const STATUS_COLOR: Record<HostStatus, string> = {
  pending: "hsl(var(--sev-medium))",
  online: "hsl(143 64% 50%)",
  offline: "hsl(var(--muted-foreground))",
  isolated: "hsl(var(--sev-critical))",
  decommissioned: "hsl(var(--muted))",
};

const OS_COLOR: Record<OsFamily, string> = {
  windows: "hsl(199 89% 60%)",
  linux: "hsl(38 92% 60%)",
  macos: "hsl(265 70% 65%)",
};

function statusBuckets(data: StatBucket[] | undefined) {
  return STATUSES.map((s) => ({
    key: s,
    label: s,
    color: STATUS_COLOR[s],
    count: data?.find((b) => b.key === s)?.count ?? 0,
  }));
}

function osBuckets(data: StatBucket[] | undefined) {
  return OS.map((o) => ({
    key: o,
    label: o,
    color: OS_COLOR[o],
    count: data?.find((b) => b.key === o)?.count ?? 0,
  }));
}

function asStatus(v: string | undefined): HostStatus | undefined {
  return v && (STATUSES as string[]).includes(v) ? (v as HostStatus) : undefined;
}

function asOs(v: string | undefined): OsFamily | undefined {
  return v && (OS as string[]).includes(v) ? (v as OsFamily) : undefined;
}

export function Hosts() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const navigate = useNavigate();

  const { state, setFilter, clearFilters, setSort, setOffset, setHiddenCols } = useTableQuery({
    limit: 50,
  });

  const filters = state.filters;
  const statusFilter = asStatus(filters.status);
  const osFilter = asOs(filters.os_family);
  const q = filters.q ?? "";

  const list = useQuery({
    queryKey: ["hosts", { ...filters, sort: state.sort, offset: state.offset, limit: state.limit }],
    queryFn: () =>
      hostsApi.list({
        status_: statusFilter,
        os_family: osFilter,
        q: q || undefined,
        sort: state.sort ? `${state.sort.id}:${state.sort.desc ? "desc" : "asc"}` : undefined,
        limit: state.limit,
        offset: state.offset,
      }),
    placeholderData: (prev) => prev,
  });

  const statusStats = useQuery({
    queryKey: ["host-stats", "status"],
    queryFn: () => hostsApi.stats("status"),
  });
  const osStats = useQuery({
    queryKey: ["host-stats", "os_family"],
    queryFn: () => hostsApi.stats("os_family"),
  });
  const versionStats = useQuery({
    queryKey: ["host-stats", "agent_version"],
    queryFn: () => hostsApi.stats("agent_version"),
  });

  const columns: ColumnDef<Host>[] = useMemo(
    () => [
      {
        id: "hostname",
        header: "Hostname",
        sortable: true,
        cell: (h) => <span className="font-medium hover:underline">{h.hostname}</span>,
      },
      {
        id: "os_family",
        header: "OS",
        sortable: true,
        cell: (h) => (
          <span className="text-sm text-muted-foreground">
            {h.os_platform ?? h.os_family} {h.os_arch ? `(${h.os_arch})` : ""}
          </span>
        ),
      },
      {
        id: "agent_version",
        header: "Agent",
        sortable: true,
        cell: (h) => (
          <span className="font-mono text-xs text-muted-foreground">{h.agent_version ?? "—"}</span>
        ),
      },
      {
        id: "status",
        header: "Status",
        sortable: true,
        cell: (h) => <HostStatusBadge status={h.status} />,
      },
      {
        id: "last_seen_at",
        header: "Last seen",
        sortable: true,
        cell: (h) => (
          <span className="text-sm text-muted-foreground">
            {h.last_seen_at ? new Date(h.last_seen_at).toLocaleString() : "never"}
          </span>
        ),
      },
      {
        id: "os_version",
        header: "OS version",
        hiddenByDefault: true,
        cell: (h) => <span className="text-xs text-muted-foreground">{h.os_version ?? "—"}</span>,
      },
      {
        id: "enrolled_at",
        header: "Enrolled",
        sortable: true,
        hiddenByDefault: true,
        cell: (h) => (
          <span className="text-xs text-muted-foreground">
            {h.enrolled_at ? new Date(h.enrolled_at).toLocaleString() : "never"}
          </span>
        ),
      },
      {
        id: "id",
        header: "ID",
        hiddenByDefault: true,
        cell: (h) => <span className="font-mono text-xs">{h.id.slice(0, 8)}</span>,
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

  const isAdmin = user?.role === "admin";

  const bulkActions: BulkAction<Host>[] | undefined = isAdmin
    ? [
        {
          id: "isolate",
          label: "Isolate",
          variant: "destructive",
          isDisabled: (sel) => sel.length === 0 || sel.every((h) => h.status === "isolated"),
          onRun: async (sel) => {
            for (const h of sel) {
              if (h.status === "isolated") continue;
              try {
                await hostsApi.update(h.id, { status: "isolated" });
              } catch (err) {
                console.error("isolate failed", h.id, err);
              }
            }
            qc.invalidateQueries({ queryKey: ["hosts"] });
            qc.invalidateQueries({ queryKey: ["host-stats"] });
          },
        },
        {
          id: "restore",
          label: "Restore",
          variant: "outline",
          isDisabled: (sel) => sel.length === 0 || sel.every((h) => h.status === "online"),
          onRun: async (sel) => {
            for (const h of sel) {
              if (h.status === "online") continue;
              try {
                await hostsApi.update(h.id, { status: "online" });
              } catch (err) {
                console.error("restore failed", h.id, err);
              }
            }
            qc.invalidateQueries({ queryKey: ["hosts"] });
            qc.invalidateQueries({ queryKey: ["host-stats"] });
          },
        },
      ]
    : undefined;

  return (
    <>
      <PageHeader title="Hosts" description={`${list.data?.total ?? 0} enrolled hosts`} />
      <div className="space-y-6 px-8 py-6">
        <div className="grid gap-4 md:grid-cols-3">
          <ChartCard title="Status" hint="Click a slice to filter">
            <DonutChart
              data={statusBuckets(statusStats.data)}
              size={130}
              activeKey={statusFilter ?? null}
              onSliceClick={(s) => setFilter("status", statusFilter === s.key ? null : s.key)}
            />
          </ChartCard>
          <ChartCard title="OS family" hint="Click a slice to filter">
            <DonutChart
              data={osBuckets(osStats.data)}
              size={130}
              activeKey={osFilter ?? null}
              onSliceClick={(s) => setFilter("os_family", osFilter === s.key ? null : s.key)}
            />
          </ChartCard>
          <ChartCard title="Agent versions">
            <BarChart
              data={(versionStats.data ?? []).map((b) => ({ key: b.key, count: b.count }))}
            />
          </ChartCard>
        </div>

        <DataTable<Host>
          tableId="hosts"
          columns={columns}
          rows={list.data?.items}
          total={list.data?.total ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No hosts yet — issue an enrollment token to add one."
          getRowId={(h) => h.id}
          onRowClick={(h) => navigate(`/hosts/${h.id}`)}
          sort={state.sort}
          onSortChange={setSort}
          offset={state.offset}
          limit={state.limit}
          onOffsetChange={setOffset}
          hiddenCols={state.hiddenCols}
          onHiddenColsChange={setHiddenCols}
          bulkActions={bulkActions}
          toolbar={
            <FilterBar
              searchKey="q"
              searchPlaceholder="Search hostname…"
              searchValue={q}
              onSearchChange={(v) => setFilter("q", v || null)}
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
