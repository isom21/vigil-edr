import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * URL-bound table state. Encodes filters, sort, page and hidden columns
 * into search params so views are shareable and back/forward works.
 *
 * Filter values are strings; the page is responsible for decoding into
 * its own typed shape (state/severity/etc.).
 */
export interface TableState {
  filters: Record<string, string>;
  sort: { id: string; desc: boolean } | null;
  offset: number;
  limit: number;
  hiddenCols: string[];
}

const DEFAULT_LIMIT = 50;

const RESERVED = new Set(["sort", "offset", "limit", "cols"]);

function parseSort(v: string | null): { id: string; desc: boolean } | null {
  if (!v) return null;
  const [id, dir] = v.split(":");
  if (!id) return null;
  return { id, desc: dir === "desc" };
}

function encodeSort(s: { id: string; desc: boolean } | null): string | null {
  if (!s) return null;
  return `${s.id}:${s.desc ? "desc" : "asc"}`;
}

export function useTableQuery(defaults: { limit?: number } = {}) {
  const [params, setParams] = useSearchParams();

  const state: TableState = useMemo(() => {
    const filters: Record<string, string> = {};
    for (const [k, v] of params.entries()) {
      if (!RESERVED.has(k) && v !== "") filters[k] = v;
    }
    return {
      filters,
      sort: parseSort(params.get("sort")),
      offset: Number(params.get("offset") ?? 0) || 0,
      limit: Number(params.get("limit") ?? defaults.limit ?? DEFAULT_LIMIT),
      hiddenCols: (params.get("cols") ?? "").split(",").filter(Boolean),
    };
  }, [params, defaults.limit]);

  const setFilter = useCallback(
    (key: string, value: string | null) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (value === null || value === "") next.delete(key);
          else next.set(key, value);
          next.delete("offset");
          return next;
        },
        { replace: false },
      );
    },
    [setParams],
  );

  const setFilters = useCallback(
    (patch: Record<string, string | null>) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(patch)) {
            if (v === null || v === "") next.delete(k);
            else next.set(k, v);
          }
          next.delete("offset");
          return next;
        },
        { replace: false },
      );
    },
    [setParams],
  );

  const clearFilters = useCallback(() => {
    setParams(
      (prev) => {
        const next = new URLSearchParams();
        const sort = prev.get("sort");
        const limit = prev.get("limit");
        const cols = prev.get("cols");
        if (sort) next.set("sort", sort);
        if (limit) next.set("limit", limit);
        if (cols) next.set("cols", cols);
        return next;
      },
      { replace: false },
    );
  }, [setParams]);

  const setSort = useCallback(
    (s: { id: string; desc: boolean } | null) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          const enc = encodeSort(s);
          if (enc) next.set("sort", enc);
          else next.delete("sort");
          return next;
        },
        { replace: false },
      );
    },
    [setParams],
  );

  const setOffset = useCallback(
    (offset: number) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (offset > 0) next.set("offset", String(offset));
          else next.delete("offset");
          return next;
        },
        { replace: false },
      );
    },
    [setParams],
  );

  const setHiddenCols = useCallback(
    (cols: string[]) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (cols.length === 0) next.delete("cols");
          else next.set("cols", cols.join(","));
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  return {
    state,
    setFilter,
    setFilters,
    clearFilters,
    setSort,
    setOffset,
    setHiddenCols,
  };
}
