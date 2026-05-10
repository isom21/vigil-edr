import { ReactNode } from "react";

export interface ColumnDef<T> {
  id: string;
  /** Header label. Falls back to id when omitted. */
  header?: string;
  /** When true the header gets a sort caret + click handler. */
  sortable?: boolean;
  /** Backend-allowed sort key — defaults to `id`. */
  sortKey?: string;
  /** Renderer for body cells. */
  cell: (row: T) => ReactNode;
  /** Hide this column by default; user can re-enable via column menu. */
  hiddenByDefault?: boolean;
  /** Optional className for the cell. */
  className?: string;
  /** Optional className for the header. */
  headerClassName?: string;
}

export interface BulkAction<T> {
  id: string;
  label: string;
  /** Disable for the current selection. Receives full row objects. */
  isDisabled?: (rows: T[]) => boolean;
  /** Variant maps to <Button variant>. */
  variant?: "default" | "outline" | "destructive" | "secondary";
  onRun: (rows: T[]) => Promise<void> | void;
}
