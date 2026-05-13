import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { incidentsApi } from "@/api/incidents";
import { ApiError } from "@/api/client";
import { SeverityBadge } from "@/components/badges";
import { DataTable, FilterBar } from "@/components/data-table";
import type { ColumnDef, FilterDef } from "@/components/data-table";
import { PageHeader } from "@/components/PageHeader";
import { useTableQuery } from "@/hooks/useTableQuery";
import { useColumnFilters } from "@/lib/table-filters";
import { cn } from "@/lib/utils";
import type { Incident, IncidentStatus } from "@/types/api";

const STATUSES: IncidentStatus[] = ["open", "investigating", "resolved", "closed"];

const FILTERS: FilterDef[] = [
  {
    key: "status",
    label: "status",
    options: STATUSES.map((s) => ({ value: s, label: s })),
  },
];

const TABLE_LIMIT = 50;

function asStatus(v: string | undefined): IncidentStatus | undefined {
  return v && (STATUSES as string[]).includes(v) ? (v as IncidentStatus) : undefined;
}

const STATUS_CLASS: Record<IncidentStatus, string> = {
  open: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  investigating: "bg-sev-low/15 text-sev-low border-sev-low/30",
  resolved: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  closed: "bg-muted text-muted-foreground border-border",
};

function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        STATUS_CLASS[status],
      )}
    >
      {status}
    </span>
  );
}

export function Incidents() {
  const navigate = useNavigate();
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();
  const { state, setFilter, clearFilters, setSort, setOffset, setLimit, setHiddenCols } =
    useTableQuery({ limit: TABLE_LIMIT });

  const filters = state.filters;
  const statusFilter = asStatus(filters.status);

  const list = useQuery({
    queryKey: [
      "incidents",
      { ...filters, sort: state.sort, offset: state.offset, limit: state.limit },
    ],
    queryFn: () =>
      incidentsApi.list({
        status: statusFilter,
        sort: state.sort ? `${state.sort.id}:${state.sort.desc ? "desc" : "asc"}` : undefined,
        limit: state.limit,
        offset: state.offset,
      }),
    placeholderData: (prev) => prev,
  });

  const columns: ColumnDef<Incident>[] = [
    {
      id: "title",
      header: "Title",
      sortable: false,
      filterValue: (i) => i.title,
      cell: (i) => <div className="max-w-md truncate font-medium">{i.title}</div>,
    },
    {
      id: "severity",
      header: "Severity",
      sortable: true,
      filterValue: (i) => i.severity,
      cell: (i) => <SeverityBadge severity={i.severity} />,
    },
    {
      id: "status",
      header: "Status",
      sortable: true,
      filterValue: (i) => i.status,
      cell: (i) => <IncidentStatusBadge status={i.status} />,
    },
    {
      id: "host",
      header: "Host",
      sortable: true,
      sortKey: "host_hostname",
      filterValue: (i) => i.host_hostname ?? i.host_id ?? "system",
      cell: (i) => {
        if (i.host_id === null) {
          return <span className="text-muted-foreground text-sm italic">System</span>;
        }
        return (
          <Link
            to={`/hosts/${i.host_id}`}
            onClick={(e) => e.stopPropagation()}
            className="truncate text-sm underline-offset-2 hover:underline"
          >
            {i.host_hostname ?? <span className="font-mono text-xs">{i.host_id.slice(0, 8)}…</span>}
          </Link>
        );
      },
    },
    {
      id: "alert_count",
      header: "Alerts",
      sortable: false,
      filterValue: (i) => i.alert_count,
      cell: (i) => <span className="font-mono text-xs tabular-nums">{i.alert_count}</span>,
    },
    {
      id: "opened_at",
      header: "Opened",
      sortable: true,
      filterValue: (i) => i.opened_at,
      cell: (i) => (
        <time
          dateTime={i.opened_at}
          className="text-sm text-muted-foreground tabular-nums whitespace-nowrap"
        >
          {new Date(i.opened_at).toLocaleString()}
        </time>
      ),
    },
    {
      id: "updated_at",
      header: "Updated",
      sortable: true,
      hiddenByDefault: true,
      filterValue: (i) => i.updated_at,
      cell: (i) => (
        <time
          dateTime={i.updated_at}
          className="text-sm text-muted-foreground tabular-nums whitespace-nowrap"
        >
          {new Date(i.updated_at).toLocaleString()}
        </time>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Incidents" description={`${list.data?.total ?? 0} grouped incidents`} />
      <div className="space-y-4 px-8 py-6">
        <DataTable<Incident>
          tableId="incidents"
          columns={columns}
          rows={list.data?.items}
          total={list.data?.total ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No incidents match the current filters."
          getRowId={(i) => i.id}
          onRowClick={(i) => navigate(`/incidents/${i.id}`)}
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
          savedFiltersTableId="incidents"
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
