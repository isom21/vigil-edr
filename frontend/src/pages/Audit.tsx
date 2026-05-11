/**
 * M22.d: audit log viewer (admin-only on the backend).
 *
 * Generic listing over /api/audit with the shared DataTable so column
 * filtering + saved sets work out of the box. Payload renders as a
 * truncated JSON snippet inline; future iteration could pop a detail
 * drawer for the full row.
 */
import { useQuery } from "@tanstack/react-query";
import { auditApi } from "@/api/audit";
import { ApiError } from "@/api/client";
import { DataTable } from "@/components/data-table";
import type { ColumnDef } from "@/components/data-table";
import { PageHeader } from "@/components/PageHeader";
import { useTableQuery } from "@/hooks/useTableQuery";
import { useColumnFilters } from "@/lib/table-filters";
import type { AuditEntry } from "@/types/api";

export function Audit() {
  const { state, setSort, setOffset, setHiddenCols } = useTableQuery({ limit: 100 });
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();

  const list = useQuery({
    queryKey: ["audit", { offset: state.offset, limit: state.limit }],
    queryFn: () => auditApi.list({ limit: state.limit, offset: state.offset }),
    placeholderData: (prev) => prev,
  });

  const columns: ColumnDef<AuditEntry>[] = [
    {
      id: "seq",
      header: "Seq",
      filterValue: (e) => e.seq,
      cell: (e) => <span className="font-mono text-xs text-muted-foreground">{e.seq}</span>,
    },
    {
      id: "ts",
      header: "Timestamp",
      filterValue: (e) => e.ts,
      cell: (e) => (
        <span className="whitespace-nowrap text-xs text-muted-foreground">
          {new Date(e.ts).toLocaleString()}
        </span>
      ),
    },
    {
      id: "actor_kind",
      header: "Actor",
      filterValue: (e) => e.actor_kind,
      cell: (e) => (
        <span className="text-xs uppercase tracking-wider text-muted-foreground">
          {e.actor_kind}
        </span>
      ),
    },
    {
      id: "action",
      header: "Action",
      filterValue: (e) => e.action,
      cell: (e) => <span className="font-mono text-xs">{e.action}</span>,
    },
    {
      id: "resource_type",
      header: "Resource type",
      filterValue: (e) => e.resource_type ?? "",
      cell: (e) => <span className="text-xs text-muted-foreground">{e.resource_type ?? "—"}</span>,
    },
    {
      id: "resource_id",
      header: "Resource id",
      filterValue: (e) => e.resource_id ?? "",
      cell: (e) => (
        <span className="font-mono text-xs text-muted-foreground">{e.resource_id ?? "—"}</span>
      ),
    },
    {
      id: "payload",
      header: "Payload",
      filterValue: (e) => JSON.stringify(e.payload ?? {}),
      cell: (e) => (
        <span className="block max-w-md truncate font-mono text-[11px] text-muted-foreground">
          {e.payload ? JSON.stringify(e.payload) : "—"}
        </span>
      ),
    },
    {
      id: "ip",
      header: "IP",
      hiddenByDefault: true,
      filterValue: (e) => e.ip ?? "",
      cell: (e) => <span className="font-mono text-xs text-muted-foreground">{e.ip ?? "—"}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every privileged action is recorded with a tamper-evident HMAC chain. Admins only."
      />
      <div className="space-y-4 px-8 py-6">
        <DataTable<AuditEntry>
          tableId="audit"
          columns={columns}
          rows={list.data?.items}
          total={list.data?.total ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No audit entries yet."
          getRowId={(e) => e.id}
          sort={state.sort}
          onSortChange={setSort}
          offset={state.offset}
          limit={state.limit}
          onOffsetChange={setOffset}
          hiddenCols={state.hiddenCols}
          onHiddenColsChange={setHiddenCols}
          columnFilters={columnFilters}
          onColumnFiltersChange={setColumnFilters}
          savedFiltersTableId="audit"
        />
      </div>
    </>
  );
}
