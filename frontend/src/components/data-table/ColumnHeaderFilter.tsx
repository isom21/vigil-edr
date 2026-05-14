/**
 * Column-header click target: opens a small floating popover that lets
 * the operator pick an operator + value and immediately add a filter.
 *
 * Renders a `<button>` so the affordance is obvious (cursor + focus
 * ring) without conflicting with the separate sort button.
 */
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { FILTER_OPS, type Filter, type FilterOp } from "@/lib/table-filters";

interface Props {
  /** Column id this filter targets. */
  colId: string;
  /** Display label. */
  label: string;
  /** Header click adds this filter via setFilter. */
  onAdd: (filter: Filter) => void;
  className?: string;
}

export function ColumnHeaderFilter({ colId, label, onAdd, className }: Props) {
  const [open, setOpen] = useState(false);
  const [op, setOp] = useState<FilterOp>("contains");
  const [value, setValue] = useState("");
  const popRef = useRef<HTMLDivElement>(null);
  const btnRef = useRef<HTMLButtonElement>(null);

  // Close on outside click or Escape.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: globalThis.MouseEvent) => {
      const t = e.target as globalThis.Node;
      if (popRef.current?.contains(t) || btnRef.current?.contains(t)) return;
      setOpen(false);
    };
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const submit = () => {
    if (!value.trim()) return;
    onAdd({ col: colId, op, value: value.trim() });
    setValue("");
    setOpen(false);
  };

  return (
    <span className={cn("relative inline-flex", className)}>
      <button
        ref={btnRef}
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className="rounded-sm px-1 py-0.5 text-left text-xs uppercase tracking-wider hover:bg-secondary/70 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        title={`Filter by ${label}`}
      >
        {label}
      </button>
      {open && (
        <div
          ref={popRef}
          // Rendered absolutely so the table layout doesn't shift when
          // the popover opens. z-50 keeps it above the sticky header.
          className="absolute left-0 top-full z-50 mt-1 w-72 rounded-md border bg-card p-3 shadow-lg"
          onClick={(e) => e.stopPropagation()}
        >
          <p className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">
            Filter {label}
          </p>
          <div className="flex flex-col gap-2">
            <Select value={op} onValueChange={(v) => setOp(v as FilterOp)}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FILTER_OPS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              autoFocus
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") submit();
              }}
              placeholder="value…"
              className="h-8 text-xs"
            />
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button size="sm" onClick={submit} disabled={!value.trim()}>
                Add filter
              </Button>
            </div>
          </div>
        </div>
      )}
    </span>
  );
}
