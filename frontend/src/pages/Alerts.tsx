import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { ALERT_TRANSITIONS, SEVERITY_HSL, severityColor, severityLabel } from "@/lib/severity";
import { AlertStateBadge, SeverityBadge } from "@/components/badges";
import { AlertBulkDialog, type BulkMode } from "@/components/AlertBulkDialog";
import { BarChart, ChartCard, DonutChart, Sparkline } from "@/components/charts";
import { DataTable, FilterBar } from "@/components/data-table";
import type { ColumnDef, BulkAction, FilterDef } from "@/components/data-table";
import { DetailDrawer } from "@/components/DetailDrawer";
import { AlertDetailPanel } from "@/components/AlertDetailPanel";
import { PageHeader } from "@/components/PageHeader";
import { useTableQuery } from "@/hooks/useTableQuery";
import { useColumnFilters } from "@/lib/table-filters";
import type { Alert, AlertState, Severity, StatBucket } from "@/types/api";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
const STATES: AlertState[] = ["new", "investigating", "false_positive", "true_positive"];

const FILTERS: FilterDef[] = [
  {
    key: "state",
    label: "state",
    options: STATES.map((s) => ({ value: s, label: s.replace("_", " ") })),
  },
  {
    key: "severity",
    label: "severity",
    options: SEVERITIES.map((s) => ({ value: s, label: s })),
  },
];

const TABLE_LIMIT = 50;

function asSeverity(v: string | undefined): Severity | undefined {
  return v && (SEVERITIES as string[]).includes(v) ? (v as Severity) : undefined;
}

function asState(v: string | undefined): AlertState | undefined {
  return v && (STATES as string[]).includes(v) ? (v as AlertState) : undefined;
}

function severityBuckets(data: StatBucket[] | undefined) {
  return SEVERITIES.map((s) => ({
    key: s,
    label: severityLabel(s),
    color: SEVERITY_HSL[s],
    count: data?.find((b) => b.key === s)?.count ?? 0,
  }));
}

const STATE_COLOR: Record<AlertState, string> = {
  new: "hsl(var(--sev-medium))",
  investigating: "hsl(var(--sev-low))",
  false_positive: "hsl(var(--muted-foreground))",
  true_positive: "hsl(var(--sev-critical))",
};

function stateBuckets(data: StatBucket[] | undefined) {
  return STATES.map((s) => ({
    key: s,
    label: s.replace("_", " "),
    color: STATE_COLOR[s],
    count: data?.find((b) => b.key === s)?.count ?? 0,
  }));
}

export function Alerts() {
  // qc previously invalidated alerts after each bulk run. M22.a moved
  // the run into AlertBulkDialog, which handles cache invalidation
  // itself; leave the import lean.
  useQueryClient(); // ensure the QueryClientProvider is mounted on this page
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();
  const { state, setFilter, clearFilters, setSort, setOffset, setLimit, setHiddenCols } =
    useTableQuery({
      limit: TABLE_LIMIT,
    });

  const filters = state.filters;
  const stateFilter = asState(filters.state);
  const severityFilter = asSeverity(filters.severity);
  const hostFilter = filters.host_hostname;
  const q = filters.q ?? "";

  const list = useQuery({
    queryKey: [
      "alerts",
      { ...filters, sort: state.sort, offset: state.offset, limit: state.limit },
    ],
    queryFn: () =>
      alertsApi.list({
        state: stateFilter,
        severity: severityFilter,
        host_hostname: hostFilter || undefined,
        q: q || undefined,
        sort: state.sort ? `${state.sort.id}:${state.sort.desc ? "desc" : "asc"}` : undefined,
        limit: state.limit,
        offset: state.offset,
      }),
    placeholderData: (prev) => prev,
  });

  const sevStats = useQuery({
    queryKey: ["alert-stats", "severity"],
    queryFn: () => alertsApi.stats("severity"),
  });
  const stateStats = useQuery({
    queryKey: ["alert-stats", "state"],
    queryFn: () => alertsApi.stats("state"),
  });
  const hourStats = useQuery({
    queryKey: ["alert-stats", "hour"],
    queryFn: () => alertsApi.stats("hour"),
  });
  const hostStats = useQuery({
    queryKey: ["alert-stats", "host"],
    queryFn: () => alertsApi.stats("host"),
  });

  const [openId, setOpenId] = useState<string | null>(null);
  // M22.a: bulk-action confirmation dialog (state transitions + assign).
  // Captured here so the BulkAction onRun handlers can pivot the user
  // to a comment/assignee prompt instead of running synchronously.
  const [bulkMode, setBulkMode] = useState<BulkMode | null>(null);
  const [bulkSelection, setBulkSelection] = useState<Alert[]>([]);

  const detail = useQuery({
    queryKey: ["alert", openId],
    queryFn: () => alertsApi.get(openId!),
    enabled: !!openId,
  });

  const rows = list.data?.items;

  // ESC closes drawer; J/K navigate (handled inside drawer too for prev/next focus).
  const openIdx = useMemo(
    () => (openId ? (rows?.findIndex((r) => r.id === openId) ?? -1) : -1),
    [rows, openId],
  );

  const columns: ColumnDef<Alert>[] = [
    {
      id: "summary",
      header: "Summary",
      sortable: false,
      filterValue: (a) => a.summary,
      cell: (a) => <div className="max-w-md truncate font-medium">{a.summary}</div>,
    },
    {
      id: "rule",
      header: "Rule",
      sortable: true,
      sortKey: "rule_name",
      filterValue: (a) => a.rule_name ?? a.rule_id,
      cell: (a) => (
        <Link
          to={`/rules/${a.rule_id}`}
          onClick={(e) => e.stopPropagation()}
          className="block max-w-xs truncate text-sm underline-offset-2 hover:underline"
        >
          {a.rule_name ?? <span className="font-mono text-xs">{a.rule_id.slice(0, 8)}…</span>}
        </Link>
      ),
    },
    {
      id: "severity",
      header: "Severity",
      sortable: true,
      filterValue: (a) => a.severity,
      cell: (a) => <SeverityBadge severity={a.severity} />,
    },
    {
      id: "state",
      header: "State",
      sortable: true,
      filterValue: (a) => a.state,
      cell: (a) => <AlertStateBadge state={a.state} />,
    },
    {
      id: "host",
      header: "Host",
      sortable: true,
      sortKey: "host_hostname",
      filterValue: (a) => a.host_hostname ?? a.host_id ?? "system",
      cell: (a) => {
        // Synthetic alerts (audit-chain break etc.) have host_id IS NULL.
        // They're admin-only and aren't attached to a host page, so
        // render an inert "System" label instead of a host link.
        if (a.host_id === null) {
          return <span className="text-muted-foreground text-sm italic">System</span>;
        }
        return (
          <Link
            to={`/hosts/${a.host_id}`}
            onClick={(e) => e.stopPropagation()}
            className="truncate text-sm underline-offset-2 hover:underline"
          >
            {a.host_hostname ?? <span className="font-mono text-xs">{a.host_id.slice(0, 8)}…</span>}
          </Link>
        );
      },
    },
    {
      id: "opened_at",
      header: "Opened",
      sortable: true,
      filterValue: (a) => a.opened_at,
      cell: (a) => (
        <time
          dateTime={a.opened_at}
          className="text-sm text-muted-foreground tabular-nums whitespace-nowrap"
        >
          {new Date(a.opened_at).toLocaleString()}
        </time>
      ),
    },
    {
      id: "action_taken",
      header: "Action",
      hiddenByDefault: true,
      filterValue: (a) => a.action_taken,
      cell: (a) => <span className="text-xs text-muted-foreground">{a.action_taken}</span>,
    },
    {
      id: "updated_at",
      header: "Updated",
      sortable: true,
      hiddenByDefault: true,
      filterValue: (a) => a.updated_at,
      cell: (a) => (
        <time
          dateTime={a.updated_at}
          className="text-sm text-muted-foreground tabular-nums whitespace-nowrap"
        >
          {new Date(a.updated_at).toLocaleString()}
        </time>
      ),
    },
    {
      id: "id",
      header: "ID",
      hiddenByDefault: true,
      filterValue: (a) => a.id,
      cell: (a) => <span className="font-mono text-xs">{a.id.slice(0, 8)}</span>,
    },
  ];

  const defaultHidden = useMemo(
    () => columns.filter((c) => c.hiddenByDefault).map((c) => c.id),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  // First load: if no `cols` param, materialise the default-hidden into URL once.
  useEffect(() => {
    if (state.hiddenCols.length === 0 && defaultHidden.length > 0) {
      setHiddenCols(defaultHidden);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const bulkActions: BulkAction<Alert>[] = [
    ...ALERT_TRANSITIONS.map(({ to, label, variant }) => ({
      id: `to-${to}`,
      label,
      variant,
      // Disable when nothing's selected OR when *any* selected row is
      // already in a state that disallows this transition. Keeps the
      // operator from accidentally trying to re-open a terminal alert.
      isDisabled: (sel: Alert[]) =>
        sel.length === 0 || sel.some((s) => !ALERT_TRANSITION_ALLOWED[s.state]?.has(to)),
      // Open the confirm/comment dialog instead of running synchronously.
      // The dialog walks the selection and reports per-row failures.
      onRun: (sel: Alert[]) => {
        setBulkSelection(sel);
        setBulkMode({ kind: "state", to, label });
      },
    })),
    {
      id: "assign",
      label: "Assign…",
      variant: "outline",
      isDisabled: (sel) => sel.length === 0,
      onRun: (sel) => {
        setBulkSelection(sel);
        setBulkMode({ kind: "assign" });
      },
    },
  ];

  const onPrev = () => {
    if (openIdx > 0 && rows) setOpenId(rows[openIdx - 1].id);
  };
  const onNext = () => {
    if (rows && openIdx >= 0 && openIdx < rows.length - 1) setOpenId(rows[openIdx + 1].id);
  };

  return (
    <>
      <PageHeader title="Alerts" description={`${list.data?.total ?? 0} matching alerts`} />

      <div className="space-y-6 px-8 py-6">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <ChartCard title="Severity" hint="Click a slice to filter">
            <DonutChart
              data={severityBuckets(sevStats.data)}
              size={130}
              activeKey={severityFilter ?? null}
              onSliceClick={(s) => setFilter("severity", severityFilter === s.key ? null : s.key)}
            />
          </ChartCard>
          <ChartCard title="State" hint="Click a slice to filter">
            <DonutChart
              data={stateBuckets(stateStats.data)}
              size={130}
              activeKey={stateFilter ?? null}
              onSliceClick={(s) => setFilter("state", stateFilter === s.key ? null : s.key)}
            />
          </ChartCard>
          <ChartCard title="Last 24h" hint="Alerts opened by hour">
            <Sparkline
              data={(hourStats.data ?? []).map((b) => ({ ts: b.key, count: b.count }))}
              width={280}
              height={80}
              color={SEVERITY_HSL.high}
              showAxis
            />
          </ChartCard>
          <ChartCard title="Top hosts" hint="Click a row to filter">
            <BarChart
              data={(hostStats.data ?? []).map((b) => ({
                key: b.key,
                count: b.count,
                color: severityColor("medium"),
              }))}
              activeKey={hostFilter ?? null}
              onBarClick={(b) => setFilter("host_hostname", hostFilter === b.key ? null : b.key)}
            />
          </ChartCard>
        </div>

        <DataTable<Alert>
          tableId="alerts"
          columns={columns}
          rows={rows}
          total={list.data?.total ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No alerts match the current filters."
          getRowId={(a) => a.id}
          onRowClick={(a) => setOpenId(a.id)}
          sort={state.sort}
          onSortChange={setSort}
          offset={state.offset}
          limit={state.limit}
          onOffsetChange={setOffset}
          onLimitChange={setLimit}
          hiddenCols={state.hiddenCols}
          onHiddenColsChange={setHiddenCols}
          bulkActions={bulkActions}
          columnFilters={columnFilters}
          onColumnFiltersChange={setColumnFilters}
          savedFiltersTableId="alerts"
          toolbar={
            <FilterBar
              searchKey="q"
              searchPlaceholder="Search summary…"
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

      <DetailDrawer
        open={!!openId}
        onOpenChange={(v) => !v && setOpenId(null)}
        title={detail.data?.summary ?? "Loading…"}
        description={openId ? `Alert ${openId.slice(0, 8)}…` : undefined}
        meta={
          detail.data && (
            <>
              <SeverityBadge severity={detail.data.severity} />
              <AlertStateBadge state={detail.data.state} />
            </>
          )
        }
        onPrev={onPrev}
        onNext={onNext}
        hasPrev={openIdx > 0}
        hasNext={!!rows && openIdx >= 0 && openIdx < rows.length - 1}
      >
        {detail.isLoading && <div className="text-muted-foreground">Loading…</div>}
        {detail.isError && (
          <div className="text-destructive">
            {detail.error instanceof ApiError ? detail.error.detail : "Failed to load."}
          </div>
        )}
        {detail.data && <AlertDetailPanel alert={detail.data} />}
      </DetailDrawer>

      <AlertBulkDialog
        open={bulkMode !== null}
        onOpenChange={(v) => !v && setBulkMode(null)}
        mode={bulkMode}
        selection={bulkSelection}
      />
    </>
  );
}

const ALERT_TRANSITION_ALLOWED: Record<AlertState, Set<AlertState>> = {
  new: new Set<AlertState>(["investigating", "false_positive", "true_positive"]),
  investigating: new Set<AlertState>(["false_positive", "true_positive", "new"]),
  false_positive: new Set<AlertState>(),
  true_positive: new Set<AlertState>(),
};
