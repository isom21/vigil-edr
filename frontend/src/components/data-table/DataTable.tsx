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
import { ColumnMenu } from "./ColumnMenu";
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
}: Props<T>) {
  const { density } = useUiPrefs();
  const cellPad = density === "compact" ? "px-3 py-1.5" : "px-4 py-3";
  const headPad = density === "compact" ? "h-9 px-3" : "h-11 px-4";

  const [selected, setSelected] = useState<Set<string>>(new Set());

  const visibleColumns = useMemo(
    () => columns.filter((c) => !hiddenCols.includes(c.id)),
    [columns, hiddenCols],
  );

  const selectableRows = useMemo(() => rows ?? [], [rows]);
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

  const onHeaderClick = (col: ColumnDef<T>) => {
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
  const start = total === 0 ? 0 : offset + 1;
  const end = Math.min(offset + limit, total);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex-1 min-w-[12rem]">{toolbar}</div>
        <ColumnMenu columns={columns} hidden={hiddenCols} onChange={onHiddenColsChange} />
      </div>

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
                return (
                  <TableHead
                    key={col.id}
                    className={cn(
                      headPad,
                      "text-xs uppercase tracking-wider",
                      col.headerClassName,
                      col.sortable && "cursor-pointer select-none hover:text-foreground",
                    )}
                    onClick={() => onHeaderClick(col)}
                  >
                    <span className="inline-flex items-center gap-1.5">
                      {col.header ?? col.id}
                      {col.sortable && (
                        <span className="text-muted-foreground">
                          {!isActive ? (
                            <ArrowUpDown className="h-3 w-3 opacity-40" />
                          ) : sort?.desc ? (
                            <ArrowDown className="h-3 w-3" />
                          ) : (
                            <ArrowUp className="h-3 w-3" />
                          )}
                        </span>
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
            {!isLoading && !isError && rows && rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={colCount} className={cn(cellPad, "text-muted-foreground")}>
                  {emptyMessage}
                </TableCell>
              </TableRow>
            )}
            {!isLoading &&
              !isError &&
              rows?.map((row) => {
                const id = getRowId(row);
                const isSelected = selected.has(id);
                return (
                  <TableRow
                    key={id}
                    data-state={isSelected ? "selected" : undefined}
                    className={cn(onRowClick && "cursor-pointer")}
                    onClick={(e) => {
                      const target = e.target as HTMLElement;
                      if (target.closest("[data-row-stop]")) return;
                      onRowClick?.(row);
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

      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <div>
          {total > 0 ? (
            <>
              Showing <span className="font-medium text-foreground">{start}</span>–
              <span className="font-medium text-foreground">{end}</span> of{" "}
              <span className="font-medium text-foreground">{total}</span>
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
