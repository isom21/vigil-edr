/**
 * M22.d: fleet-wide quarantine inventory.
 *
 * Mirrors HostQuarantinePanel but across every host the actor can
 * see, using the shared DataTable so the column-filter primitives
 * + saved sets just work.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError } from "@/api/client";
import { quarantineApi } from "@/api/quarantine";
import { DataTable } from "@/components/data-table";
import type { BulkAction, ColumnDef } from "@/components/data-table";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { useTableQuery } from "@/hooks/useTableQuery";
import { useColumnFilters } from "@/lib/table-filters";
import { cn } from "@/lib/utils";
import type { QuarantinedFile, QuarantineStatus } from "@/types/api";

const STATUS_CLASS: Record<QuarantineStatus, string> = {
  active: "bg-amber-500/15 text-amber-500 border-amber-500/30",
  released: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  deleted: "bg-muted text-muted-foreground border-border",
};

export function Quarantine() {
  const qc = useQueryClient();
  const { state, setSort, setOffset, setHiddenCols } = useTableQuery({ limit: 100 });
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();
  const [error, setError] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["quarantine-fleet", { offset: state.offset, limit: state.limit }],
    queryFn: () => quarantineApi.list({ limit: state.limit, offset: state.offset }),
    placeholderData: (prev) => prev,
  });

  const release = useMutation({
    mutationFn: (id: string) => quarantineApi.release(id, {}),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["quarantine-fleet"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const columns: ColumnDef<QuarantinedFile>[] = [
    {
      id: "original_path",
      header: "Original path",
      filterValue: (f) => f.original_path,
      cell: (f) => <span className="font-mono break-all text-xs">{f.original_path}</span>,
    },
    {
      id: "host_id",
      header: "Host",
      filterValue: (f) => f.host_id,
      cell: (f) => (
        <Link
          to={`/hosts/${f.host_id}`}
          onClick={(e) => e.stopPropagation()}
          className="font-mono text-xs underline-offset-2 hover:underline"
        >
          {f.host_id.slice(0, 8)}…
        </Link>
      ),
    },
    {
      id: "sha256",
      header: "SHA-256",
      filterValue: (f) => f.sha256,
      cell: (f) => (
        <span className="font-mono text-xs text-muted-foreground" title={f.sha256}>
          {f.sha256.slice(0, 12)}…
        </span>
      ),
    },
    {
      id: "size_bytes",
      header: "Size",
      filterValue: (f) => f.size_bytes,
      cell: (f) => <span className="font-mono text-xs text-muted-foreground">{f.size_bytes}</span>,
    },
    {
      id: "quarantined_at",
      header: "Quarantined",
      sortable: false,
      filterValue: (f) => f.quarantined_at,
      cell: (f) => (
        <span className="whitespace-nowrap text-xs text-muted-foreground">
          {new Date(f.quarantined_at).toLocaleString()}
        </span>
      ),
    },
    {
      id: "status",
      header: "Status",
      filterValue: (f) => f.status,
      cell: (f) => (
        <span
          className={cn(
            "inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium",
            STATUS_CLASS[f.status],
          )}
        >
          {f.status}
        </span>
      ),
    },
    {
      id: "actions",
      header: "Actions",
      cell: (f) =>
        f.status === "active" ? (
          <Button
            size="sm"
            variant="outline"
            onClick={(e) => {
              e.stopPropagation();
              release.mutate(f.id);
            }}
            disabled={release.isPending && release.variables === f.id}
          >
            {release.isPending && release.variables === f.id ? "Releasing…" : "Release"}
          </Button>
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
  ];

  const bulkActions: BulkAction<QuarantinedFile>[] = [
    {
      id: "release-bulk",
      label: "Release",
      variant: "outline",
      isDisabled: (sel) => sel.length === 0 || sel.every((f) => f.status !== "active"),
      onRun: async (sel) => {
        for (const f of sel) {
          if (f.status !== "active") continue;
          try {
            await quarantineApi.release(f.id, {});
          } catch (e) {
            console.error("release failed", f.id, e);
          }
        }
        qc.invalidateQueries({ queryKey: ["quarantine-fleet"] });
      },
    },
  ];

  return (
    <>
      <PageHeader
        title="Quarantine"
        description={`${list.data?.total ?? 0} quarantined files across the fleet`}
      />
      <div className="space-y-4 px-8 py-6">
        {error && (
          <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}
        <DataTable<QuarantinedFile>
          tableId="quarantine"
          columns={columns}
          rows={list.data?.items}
          total={list.data?.total ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No quarantined files."
          getRowId={(f) => f.id}
          sort={state.sort}
          onSortChange={setSort}
          offset={state.offset}
          limit={state.limit}
          onOffsetChange={setOffset}
          hiddenCols={state.hiddenCols}
          onHiddenColsChange={setHiddenCols}
          bulkActions={bulkActions}
          columnFilters={columnFilters}
          onColumnFiltersChange={setColumnFilters}
          savedFiltersTableId="quarantine"
        />
      </div>
    </>
  );
}
