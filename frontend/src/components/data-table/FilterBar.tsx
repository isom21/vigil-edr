import { useEffect, useState } from "react";
import { Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export interface FilterDef {
  /** URL key + identity. */
  key: string;
  /** Pretty label shown in chips. */
  label: string;
  options: { value: string; label: string }[];
}

interface Props {
  /** Optional free-text search. The page chooses which backend filter receives it. */
  searchKey?: string;
  searchPlaceholder?: string;
  searchValue?: string;
  onSearchChange?: (v: string) => void;
  filters: FilterDef[];
  values: Record<string, string>;
  onFilterChange: (key: string, value: string | null) => void;
  onClearAll: () => void;
}

function DebouncedSearch({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const [local, setLocal] = useState(value);

  useEffect(() => {
    setLocal(value);
  }, [value]);

  useEffect(() => {
    if (local === value) return;
    const t = window.setTimeout(() => onChange(local), 250);
    return () => window.clearTimeout(t);
  }, [local, value, onChange]);

  return (
    <div className="relative w-full max-w-sm">
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={local}
        onChange={(e) => setLocal(e.target.value)}
        placeholder={placeholder}
        className="pl-9"
      />
    </div>
  );
}

export function FilterBar({
  searchKey,
  searchPlaceholder,
  searchValue,
  onSearchChange,
  filters,
  values,
  onFilterChange,
  onClearAll,
}: Props) {
  const activeChips = Object.entries(values).filter(([k]) => k !== searchKey && values[k]);
  const search = searchKey ? (values[searchKey] ?? searchValue ?? "") : "";

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        {searchKey && onSearchChange && (
          <DebouncedSearch
            value={search}
            onChange={onSearchChange}
            placeholder={searchPlaceholder}
          />
        )}
        {filters.map((f) => {
          const v = values[f.key] ?? "";
          return (
            <select
              key={f.key}
              value={v}
              onChange={(e) => onFilterChange(f.key, e.target.value || null)}
              className={cn(
                "h-9 rounded-md border border-input bg-background px-3 text-sm",
                v && "border-primary/40",
              )}
            >
              <option value="">all {f.label}</option>
              {f.options.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          );
        })}
      </div>
      {(activeChips.length > 0 || (searchKey && search)) && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">Filters:</span>
          {searchKey && search && (
            <FilterChip label={`search: ${search}`} onRemove={() => onSearchChange?.("")} />
          )}
          {activeChips.map(([k, v]) => {
            const def = filters.find((f) => f.key === k);
            const optLabel = def?.options.find((o) => o.value === v)?.label ?? v;
            const label = def ? `${def.label}: ${optLabel}` : `${k}: ${v}`;
            return <FilterChip key={k} label={label} onRemove={() => onFilterChange(k, null)} />;
          })}
          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={onClearAll}>
            Clear all
          </Button>
        </div>
      )}
    </div>
  );
}

function FilterChip({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border bg-secondary/50 px-2 py-0.5 text-foreground">
      {label}
      <button
        type="button"
        aria-label={`Remove ${label}`}
        onClick={onRemove}
        className="text-muted-foreground hover:text-foreground"
      >
        <X className="h-3 w-3" />
      </button>
    </span>
  );
}
