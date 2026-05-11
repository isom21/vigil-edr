import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useUiPrefs } from "@/hooks/useUiPrefs";
import { cn } from "@/lib/utils";
import { applyFilters, type Filter } from "@/lib/table-filters";
import { ColumnHeaderFilter } from "./ColumnHeaderFilter";
import { ColumnMenu } from "./ColumnMenu";
import { FilterChipBar } from "./FilterChipBar";
import type { BulkAction, ColumnDef } from "./types";

interface Props<T> {
  /** Stable id; used to namespace localStorage keys. */
  tableId: string;
  columns: ColumnDef<T>[];
  rows: T[] | undefined;
  total: number;
  isLoading?: boolean;
  isError?: boolean;
  errorMessage?: string;
  emptyMessage?: string;
  getRowId: (row: T) => string;
  /** Click handler. If provided, rows become clickable. */
  onRowClick?: (row: T) => void;
  /** Sort state from useTableQuery. */
  sort: { id: string; desc: boolean } | null;
  onSortChange: (s: { id: string; desc: boolean } | null) => void;
  /** Pagination from useTableQuery. */
  offset: number;
  limit: number;
  onOffsetChange: (offset: number) => void;
  /** Hidden column ids. */
  hiddenCols: string[];
  onHiddenColsChange: (cols: string[]) => void;
  /** Bulk actions enable selection column. */
  bulkActions?: BulkAction<T>[];
  /** Optional toolbar slot rendered above the table (filters, search, etc.). */
  toolbar?: React.ReactNode;
  /**
   * Column-filter state (M20.k). When `columnFilters` is wired the
   * table renders the chip bar + per-column popovers and applies the
   * filters client-side to the page of rows. Wire from
   * `useColumnFilters()`.
   */
  columnFilters?: Filter[];
  onColumnFiltersChange?: (filters: Filter[]) => void;
  /**
   * When supplied, the chip bar exposes "Save set" / saved-set picker
   * scoped to this tableId via localStorage.
   */
  savedFiltersTableId?: string;
}

export function DataTable<T>({
  tableId,
  columns,
  rows,
  total,
  isLoading,
  isError,
  errorMessage,
  emptyMessage = "No results.",
  getRowId,
  onRowClick,
  sort,
  onSortChange,
  offset,
  limit,
  onOffsetChange,
  hiddenCols,
  onHiddenColsChange,
  bulkActions,
  toolbar,
  columnFilters,
  onColumnFiltersChange,
  savedFiltersTableId,
}: Props<T>) {
  const { density } = useUiPrefs();
  const cellPad = density === "compact" ? "px-3 py-1.5" : "px-4 py-3";
  const headPad = density === "compact" ? "h-9 px-3" : "h-11 px-4";

  const [selected, setSelected] = useState<Set<string>>(new Set());

  const visibleColumns = useMemo(
    () => columns.filter((c) => !hiddenCols.includes(c.id)),
    [columns, hiddenCols],
  );

  // M20.k: build a (col -> filterValue) accessor table from ColumnDef
  // so the engine can pull the right field for arbitrary column ids.
  const accessors = useMemo(() => {
    const m = new Map<string, (row: T) => unknown>();
    for (const c of columns) {
      if (c.filterValue) m.set(c.id, c.filterValue);
    }
    return m;
  }, [columns]);
  const columnLabels = useMemo(() => {
    const m: Record<string, string> = {};
    for (const c of columns) m[c.id] = c.header ?? c.id;
    return m;
  }, [columns]);

  const filteredRows = useMemo(() => {
    if (!rows) return rows;
    if (!columnFilters || columnFilters.length === 0) return rows;
    return applyFilters(rows, columnFilters, (row, col) => accessors.get(col)?.(row));
  }, [rows, columnFilters, accessors]);

  const selectableRows = useMemo(() => filteredRows ?? [], [filteredRows]);
  const allSelected =
    selectableRows.length > 0 && selectableRows.every((r) => selected.has(getRowId(r)));

  const toggleAll = () => {
    setSelected(() => {
      if (allSelected) return new Set();
      return new Set(selectableRows.map(getRowId));
    });
  };
  const toggleOne = (id: string) =>
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const clearSelection = () => setSelected(new Set());

  const selectedRows = useMemo(
    () => selectableRows.filter((r) => selected.has(getRowId(r))),
    [selectableRows, selected, getRowId],
  );

  const cycleSort = (col: ColumnDef<T>) => {
    if (!col.sortable) return;
    const key = col.sortKey ?? col.id;
    if (!sort || sort.id !== key) {
      onSortChange({ id: key, desc: true });
    } else if (sort.desc) {
      onSortChange({ id: key, desc: false });
    } else {
      onSortChange(null);
    }
  };

  const colCount = visibleColumns.length + (bulkActions ? 1 : 0);
  // M20.k: when client-side filters narrow the page we want the
  // pagination footer to reflect what's actually shown, not the
  // server-reported total. Effective total = server total when no
  // filter is active, otherwise the filtered length on this page.
  const filterActive = !!(columnFilters && columnFilters.length > 0);
  const effectiveTotal = filterActive ? (filteredRows?.length ?? 0) : total;
  const start = effectiveTotal === 0 ? 0 : offset + 1;
  const end = filterActive ? offset + (filteredRows?.length ?? 0) : Math.min(offset + limit, total);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex-1 min-w-[12rem]">{toolbar}</div>
        <ColumnMenu columns={columns} hidden={hiddenCols} onChange={onHiddenColsChange} />
      </div>

      {onColumnFiltersChange && savedFiltersTableId && (
        <FilterChipBar
          tableId={savedFiltersTableId}
          filters={columnFilters ?? []}
          columnLabels={columnLabels}
          onRemove={(idx) =>
            onColumnFiltersChange((columnFilters ?? []).filter((_, i) => i !== idx))
          }
          onClear={() => onColumnFiltersChange([])}
          onApply={(fs) => onColumnFiltersChange(fs)}
        />
      )}

      {bulkActions && selectedRows.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border bg-secondary/40 px-3 py-2 text-sm">
          <span className="font-medium">{selectedRows.length} selected</span>
          <div className="ml-auto flex flex-wrap gap-2">
            {bulkActions.map((a) => (
              <Button
                key={a.id}
                size="sm"
                variant={a.variant ?? "outline"}
                disabled={a.isDisabled?.(selectedRows) ?? false}
                onClick={async () => {
                  await a.onRun(selectedRows);
                  clearSelection();
                }}
              >
                {a.label}
              </Button>
            ))}
            <Button size="sm" variant="ghost" onClick={clearSelection}>
              Clear
            </Button>
          </div>
        </div>
      )}

      <div className="overflow-hidden rounded-md border">
        <Table>
          <TableHeader>
            <TableRow className="bg-secondary/30 hover:bg-secondary/30">
              {bulkActions && (
                <TableHead className={cn(headPad, "w-10")}>
                  <input
                    type="checkbox"
                    aria-label="Select all on page"
                    className="h-4 w-4 cursor-pointer accent-primary"
                    checked={allSelected}
                    onChange={toggleAll}
                  />
                </TableHead>
              )}
              {visibleColumns.map((col) => {
                const sortKey = col.sortKey ?? col.id;
                const isActive = sort && sort.id === sortKey;
                const label = col.header ?? col.id;
                const filterable = !!(col.filterValue && onColumnFiltersChange);
                return (
                  <TableHead
                    key={col.id}
                    className={cn(headPad, "text-xs uppercase tracking-wider", col.headerClassName)}
                  >
                    <span className="inline-flex items-center gap-1">
                      {filterable ? (
                        <ColumnHeaderFilter
                          colId={col.id}
                          label={label}
                          onAdd={(f) => onColumnFiltersChange!([...(columnFilters ?? []), f])}
                        />
                      ) : (
                        <span>{label}</span>
                      )}
                      {col.sortable && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            cycleSort(col);
                          }}
                          className="rounded-sm p-0.5 text-muted-foreground hover:bg-secondary/70 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                          title={isActive ? "Sorted — click to cycle" : "Sort by this column"}
                          aria-label={`Sort by ${label}`}
                        >
                          {!isActive ? (
                            <ArrowUpDown className="h-3 w-3 opacity-50" />
                          ) : sort?.desc ? (
                            <ArrowDown className="h-3 w-3" />
                          ) : (
                            <ArrowUp className="h-3 w-3" />
                          )}
                        </button>
                      )}
                    </span>
                  </TableHead>
                );
              })}
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading && (
              <TableRow>
                <TableCell colSpan={colCount} className={cn(cellPad, "text-muted-foreground")}>
                  Loading…
                </TableCell>
              </TableRow>
            )}
            {!isLoading && isError && (
              <TableRow>
                <TableCell colSpan={colCount} className={cn(cellPad, "text-destructive")}>
                  {errorMessage ?? "Failed to load."}
                </TableCell>
              </TableRow>
            )}
            {!isLoading && !isError && filteredRows && filteredRows.length === 0 && (
              <TableRow>
                <TableCell colSpan={colCount} className={cn(cellPad, "text-muted-foreground")}>
                  {filterActive && rows && rows.length > 0
                    ? `No rows on this page match the ${columnFilters?.length} active filter${columnFilters?.length === 1 ? "" : "s"}.`
                    : emptyMessage}
                </TableCell>
              </TableRow>
            )}
            {!isLoading &&
              !isError &&
              filteredRows?.map((row) => {
                const id = getRowId(row);
                const isSelected = selected.has(id);
                return (
                  <TableRow
                    key={id}
                    data-state={isSelected ? "selected" : undefined}
                    className={cn(
                      onRowClick &&
                        "cursor-pointer focus-visible:bg-secondary/40 focus-visible:outline-none",
                    )}
                    role={onRowClick ? "button" : undefined}
                    tabIndex={onRowClick ? 0 : undefined}
                    onClick={(e) => {
                      const target = e.target as HTMLElement;
                      if (target.closest("[data-row-stop]")) return;
                      onRowClick?.(row);
                    }}
                    onKeyDown={(e) => {
                      if (!onRowClick) return;
                      if (e.key === "Enter" || e.key === " ") {
                        const target = e.target as HTMLElement;
                        if (target.closest("[data-row-stop]")) return;
                        e.preventDefault();
                        onRowClick(row);
                      }
                    }}
                  >
                    {bulkActions && (
                      <TableCell className={cn(cellPad, "w-10")} data-row-stop="true">
                        <input
                          type="checkbox"
                          aria-label="Select row"
                          className="h-4 w-4 cursor-pointer accent-primary"
                          checked={isSelected}
                          onChange={() => toggleOne(id)}
                          onClick={(e) => e.stopPropagation()}
                        />
                      </TableCell>
                    )}
                    {visibleColumns.map((col) => (
                      <TableCell key={col.id} className={cn(cellPad, col.className)}>
                        {col.cell(row)}
                      </TableCell>
                    ))}
                  </TableRow>
                );
              })}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between text-sm text-muted-foreground tabular-nums">
        <div>
          {effectiveTotal > 0 ? (
            <>
              Showing <span className="font-medium text-foreground">{start}</span>–
              <span className="font-medium text-foreground">{end}</span> of{" "}
              <span className="font-medium text-foreground">{effectiveTotal}</span>
              {filterActive && total !== effectiveTotal && (
                <span className="ml-1">({total} on server, filtered locally)</span>
              )}
            </>
          ) : (
            "0 results"
          )}
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="sm"
            disabled={offset === 0}
            onClick={() => onOffsetChange(Math.max(0, offset - limit))}
          >
            <ChevronLeft className="h-4 w-4" />
            Prev
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={offset + limit >= total}
            onClick={() => onOffsetChange(offset + limit)}
          >
            Next
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
      {/* Tracker for tableId is reserved for future per-table localStorage prefs. */}
      <span className="hidden" data-table-id={tableId} />
    </div>
  );
}
