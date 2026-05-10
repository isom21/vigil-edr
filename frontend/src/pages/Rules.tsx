import { useEffect, useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { rulesApi } from "@/api/rules";
import { ApiError } from "@/api/client";
import { RuleActionBadge, SeverityBadge } from "@/components/badges";
import { SEVERITY_HSL } from "@/lib/severity";
import { ChartCard, DonutChart } from "@/components/charts";
import { DataTable, FilterBar } from "@/components/data-table";
import type { BulkAction, ColumnDef, FilterDef } from "@/components/data-table";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";
import { useTableQuery } from "@/hooks/useTableQuery";
import type { Rule, RuleKind, Severity, StatBucket } from "@/types/api";

const KINDS: RuleKind[] = ["yara", "sigma", "ioc"];
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

const FILTERS: FilterDef[] = [
  {
    key: "kind",
    label: "kind",
    options: KINDS.map((k) => ({ value: k, label: k.toUpperCase() })),
  },
  {
    key: "enabled",
    label: "enabled",
    options: [
      { value: "true", label: "enabled" },
      { value: "false", label: "disabled" },
    ],
  },
];

const KIND_COLOR: Record<RuleKind, string> = {
  yara: "hsl(var(--sev-low))",
  sigma: "hsl(var(--sev-high))",
  ioc: "hsl(var(--sev-medium))",
};

function severityBuckets(data: StatBucket[] | undefined) {
  return SEVERITIES.map((s) => ({
    key: s,
    label: s,
    color: SEVERITY_HSL[s],
    count: data?.find((b) => b.key === s)?.count ?? 0,
  }));
}

function kindBuckets(data: StatBucket[] | undefined) {
  return KINDS.map((k) => ({
    key: k,
    label: k.toUpperCase(),
    color: KIND_COLOR[k],
    count: data?.find((b) => b.key === k)?.count ?? 0,
  }));
}

function enabledBuckets(data: StatBucket[] | undefined) {
  return [
    {
      key: "enabled",
      label: "enabled",
      color: "hsl(143 64% 50%)",
      count: data?.find((b) => b.key === "enabled")?.count ?? 0,
    },
    {
      key: "disabled",
      label: "disabled",
      color: "hsl(var(--muted-foreground))",
      count: data?.find((b) => b.key === "disabled")?.count ?? 0,
    },
  ];
}

function asKind(v: string | undefined): RuleKind | undefined {
  return v && (KINDS as string[]).includes(v) ? (v as RuleKind) : undefined;
}

export function Rules() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { state, setFilter, clearFilters, setSort, setOffset, setHiddenCols } = useTableQuery({
    limit: 50,
  });

  const filters = state.filters;
  const kindFilter = asKind(filters.kind);
  const enabledFilter =
    filters.enabled === "true" ? true : filters.enabled === "false" ? false : undefined;
  const q = filters.q ?? "";

  const list = useQuery({
    queryKey: ["rules", { ...filters, sort: state.sort, offset: state.offset, limit: state.limit }],
    queryFn: () =>
      rulesApi.list({
        kind: kindFilter,
        enabled: enabledFilter,
        q: q || undefined,
        sort: state.sort ? `${state.sort.id}:${state.sort.desc ? "desc" : "asc"}` : undefined,
        limit: state.limit,
        offset: state.offset,
      }),
    placeholderData: (prev) => prev,
  });

  const kindStats = useQuery({
    queryKey: ["rule-stats", "kind"],
    queryFn: () => rulesApi.stats("kind"),
  });
  const sevStats = useQuery({
    queryKey: ["rule-stats", "severity"],
    queryFn: () => rulesApi.stats("severity"),
  });
  const enabledStats = useQuery({
    queryKey: ["rule-stats", "enabled"],
    queryFn: () => rulesApi.stats("enabled"),
  });

  const isAdmin = user?.role === "admin";

  const columns: ColumnDef<Rule>[] = useMemo(
    () => [
      {
        id: "name",
        header: "Name",
        sortable: true,
        cell: (r) => (
          <div className="max-w-md">
            <div className="truncate font-medium">{r.name}</div>
            {r.description && (
              <div className="truncate text-xs text-muted-foreground">{r.description}</div>
            )}
          </div>
        ),
      },
      {
        id: "kind",
        header: "Kind",
        sortable: true,
        cell: (r) => (
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {r.kind}
          </span>
        ),
      },
      {
        id: "severity",
        header: "Severity",
        sortable: true,
        cell: (r) => <SeverityBadge severity={r.severity} />,
      },
      {
        id: "action",
        header: "Action",
        cell: (r) => <RuleActionBadge action={r.action} />,
      },
      {
        id: "enabled",
        header: "Enabled",
        sortable: true,
        cell: (r) => (
          <span
            className={
              r.enabled
                ? "text-emerald-500 text-xs font-medium"
                : "text-muted-foreground text-xs font-medium"
            }
          >
            {r.enabled ? "enabled" : "disabled"}
          </span>
        ),
      },
      {
        id: "updated_at",
        header: "Updated",
        sortable: true,
        cell: (r) => (
          <span className="text-sm text-muted-foreground">
            {new Date(r.updated_at).toLocaleString()}
          </span>
        ),
      },
      {
        id: "revision",
        header: "Rev",
        hiddenByDefault: true,
        cell: (r) => <span className="font-mono text-xs text-muted-foreground">{r.revision}</span>,
      },
      {
        id: "iocs",
        header: "IOCs",
        hiddenByDefault: true,
        cell: (r) => <span className="text-xs text-muted-foreground">{r.iocs.length}</span>,
      },
    ],
    [],
  );

  const defaultHidden = useMemo(
    () => columns.filter((c) => c.hiddenByDefault).map((c) => c.id),
    [columns],
  );

  useEffect(() => {
    if (state.hiddenCols.length === 0 && defaultHidden.length > 0) {
      setHiddenCols(defaultHidden);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const bulkActions: BulkAction<Rule>[] | undefined = isAdmin
    ? [
        {
          id: "enable",
          label: "Enable",
          variant: "outline",
          isDisabled: (sel) => sel.length === 0 || sel.every((r) => r.enabled),
          onRun: async (sel) => {
            for (const r of sel) {
              if (r.enabled) continue;
              try {
                await rulesApi.update(r.id, { enabled: true });
              } catch (err) {
                console.error("enable failed", r.id, err);
              }
            }
            qc.invalidateQueries({ queryKey: ["rules"] });
            qc.invalidateQueries({ queryKey: ["rule-stats"] });
          },
        },
        {
          id: "disable",
          label: "Disable",
          variant: "secondary",
          isDisabled: (sel) => sel.length === 0 || sel.every((r) => !r.enabled),
          onRun: async (sel) => {
            for (const r of sel) {
              if (!r.enabled) continue;
              try {
                await rulesApi.update(r.id, { enabled: false });
              } catch (err) {
                console.error("disable failed", r.id, err);
              }
            }
            qc.invalidateQueries({ queryKey: ["rules"] });
            qc.invalidateQueries({ queryKey: ["rule-stats"] });
          },
        },
      ]
    : undefined;

  return (
    <>
      <PageHeader
        title="Rules"
        description="Detection content evaluated by agents and the streaming pipeline."
        actions={
          isAdmin && (
            <Button asChild>
              <Link to={`/rules/new?kind=${kindFilter ?? "yara"}`}>
                <Plus className="h-4 w-4" />
                New rule
              </Link>
            </Button>
          )
        }
      />
      <div className="space-y-6 px-8 py-6">
        <div className="grid gap-4 md:grid-cols-3">
          <ChartCard title="Kind">
            <DonutChart
              data={kindBuckets(kindStats.data)}
              size={130}
              activeKey={kindFilter ?? null}
              onSliceClick={(s) => setFilter("kind", kindFilter === s.key ? null : s.key)}
            />
          </ChartCard>
          <ChartCard title="Severity">
            <DonutChart data={severityBuckets(sevStats.data)} size={130} />
          </ChartCard>
          <ChartCard title="Enabled">
            <DonutChart
              data={enabledBuckets(enabledStats.data)}
              size={130}
              activeKey={
                filters.enabled === "true"
                  ? "enabled"
                  : filters.enabled === "false"
                    ? "disabled"
                    : null
              }
              onSliceClick={(s) => {
                const next = s.key === "enabled" ? "true" : "false";
                setFilter("enabled", filters.enabled === next ? null : next);
              }}
            />
          </ChartCard>
        </div>

        <DataTable<Rule>
          tableId="rules"
          columns={columns}
          rows={list.data?.items}
          total={list.data?.total ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No rules match the current filters."
          getRowId={(r) => r.id}
          onRowClick={(r) => navigate(`/rules/${r.id}`)}
          sort={state.sort}
          onSortChange={setSort}
          offset={state.offset}
          limit={state.limit}
          onOffsetChange={setOffset}
          hiddenCols={state.hiddenCols}
          onHiddenColsChange={setHiddenCols}
          bulkActions={bulkActions}
          toolbar={
            <FilterBar
              searchKey="q"
              searchPlaceholder="Search rules…"
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
    </>
  );
}
