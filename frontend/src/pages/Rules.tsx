/**
 * M20.g: rule taxonomy view.
 *
 * Three top-level sections (YARA / Sigma / IOC). Each kind shows its
 * `rule_groups` as cards with a `max_action` ceiling chip plus inline
 * edit/delete, then the rules inside that group, then an "Ungrouped"
 * bucket for kind-rules that haven't been assigned to a group yet.
 *
 * Effective action is computed client-side from `min(rule.action,
 * group.max_action)` so the operator can see at a glance what'll
 * actually fire — matches the backend `clamp_action` logic.
 */
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, MoreHorizontal, Pencil, Plus, Trash2 } from "lucide-react";
import { rulesApi } from "@/api/rules";
import { ruleGroupsApi } from "@/api/ruleGroups";
import { ApiError } from "@/api/client";
import { RuleActionBadge, SeverityBadge } from "@/components/badges";
import { ColumnHeaderFilter } from "@/components/data-table/ColumnHeaderFilter";
import { FilterChipBar } from "@/components/data-table/FilterChipBar";
import { PageHeader } from "@/components/PageHeader";
import { RuleGroupDialog } from "@/components/RuleGroupDialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/hooks/useAuth";
import { applyFilters, useColumnFilters } from "@/lib/table-filters";
import { cn } from "@/lib/utils";
import type { Rule, RuleAction, RuleGroup, RuleKind } from "@/types/api";

// Filterable columns inside each rule group's inline table.
const RULE_COLUMNS: { id: string; label: string; accessor: (r: Rule) => unknown }[] = [
  { id: "name", label: "name", accessor: (r) => `${r.name} ${r.description ?? ""}` },
  { id: "severity", label: "severity", accessor: (r) => r.severity },
  { id: "action", label: "action", accessor: (r) => r.action },
  { id: "enabled", label: "enabled", accessor: (r) => (r.enabled ? "enabled" : "disabled") },
];
const RULE_LABELS = Object.fromEntries(RULE_COLUMNS.map((c) => [c.id, c.label]));

const KINDS: RuleKind[] = ["yara", "sigma", "ioc"];
const KIND_LABEL: Record<RuleKind, string> = { yara: "YARA", sigma: "Sigma", ioc: "IOC" };
const ACTION_ORDER: Record<RuleAction, number> = { alert: 0, block: 1, quarantine: 2 };

function effectiveAction(rule: Rule, ceiling: RuleAction | null): RuleAction {
  if (ceiling == null) return rule.action;
  return ACTION_ORDER[rule.action] <= ACTION_ORDER[ceiling] ? rule.action : ceiling;
}

export function Rules() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  // Dialog state lifted to the page so create/edit can be triggered
  // from either kind section or group header.
  const [dialogState, setDialogState] = useState<
    { mode: "create"; kind: RuleKind } | { mode: "edit"; group: RuleGroup } | null
  >(null);

  // Column filters apply to every group's rule table on the page.
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();

  return (
    <>
      <PageHeader
        title="Rules"
        description="Detection content evaluated by agents and the streaming pipeline. Grouped by kind and rule group; group ceilings clamp the action any contained rule can take."
        actions={
          isAdmin && (
            <Button asChild>
              <Link to="/rules/new?kind=yara">
                <Plus className="h-4 w-4" />
                New rule
              </Link>
            </Button>
          )
        }
      />
      <div className="mx-auto w-full max-w-[1600px] space-y-8 px-6 py-6">
        <FilterChipBar
          tableId="rules"
          filters={columnFilters}
          columnLabels={RULE_LABELS}
          onRemove={(i) => setColumnFilters(columnFilters.filter((_, j) => j !== i))}
          onClear={() => setColumnFilters([])}
          onApply={setColumnFilters}
        />
        {KINDS.map((kind) => (
          <KindSection
            key={kind}
            kind={kind}
            isAdmin={isAdmin}
            columnFilters={columnFilters}
            setColumnFilters={setColumnFilters}
            onCreateGroup={() => setDialogState({ mode: "create", kind })}
            onEditGroup={(group) => setDialogState({ mode: "edit", group })}
          />
        ))}
      </div>
      {dialogState && (
        <RuleGroupDialog
          open={true}
          onOpenChange={(v) => !v && setDialogState(null)}
          kind={dialogState.mode === "create" ? dialogState.kind : undefined}
          group={dialogState.mode === "edit" ? dialogState.group : undefined}
        />
      )}
    </>
  );
}

function KindSection({
  kind,
  isAdmin,
  columnFilters,
  setColumnFilters,
  onCreateGroup,
  onEditGroup,
}: {
  kind: RuleKind;
  isAdmin: boolean;
  columnFilters: import("@/lib/table-filters").Filter[];
  setColumnFilters: (f: import("@/lib/table-filters").Filter[]) => void;
  onCreateGroup: () => void;
  onEditGroup: (g: RuleGroup) => void;
}) {
  const groups = useQuery({
    queryKey: ["rule-groups", kind],
    queryFn: () => ruleGroupsApi.list({ kind, limit: 100 }),
  });
  const allRules = useQuery({
    queryKey: ["rules", { kind }],
    queryFn: () => rulesApi.list({ kind, limit: 500 }),
  });

  const rules = allRules.data?.items ?? [];
  const groupItems = groups.data?.items ?? [];
  const ungrouped = rules.filter((r) => r.group_id == null);

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between border-b pb-2">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">
            {KIND_LABEL[kind]}{" "}
            <span className="text-sm font-normal text-muted-foreground">
              · {rules.length} rule{rules.length === 1 ? "" : "s"} · {groupItems.length} group
              {groupItems.length === 1 ? "" : "s"}
            </span>
          </h2>
        </div>
        {isAdmin && (
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={onCreateGroup}>
              <Plus className="h-3.5 w-3.5" />
              New group
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link to={`/rules/new?kind=${kind}`}>
                <Plus className="h-3.5 w-3.5" />
                New rule
              </Link>
            </Button>
          </div>
        )}
      </div>

      {groups.isLoading || allRules.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <div className="space-y-3">
          {groupItems.map((g) => (
            <GroupCard
              key={g.id}
              group={g}
              rules={rules.filter((r) => r.group_id === g.id)}
              isAdmin={isAdmin}
              kindGroups={groupItems}
              columnFilters={columnFilters}
              setColumnFilters={setColumnFilters}
              onEdit={() => onEditGroup(g)}
            />
          ))}
          {ungrouped.length > 0 && (
            <GroupCard
              group={null}
              rules={ungrouped}
              isAdmin={isAdmin}
              kindGroups={groupItems}
              columnFilters={columnFilters}
              setColumnFilters={setColumnFilters}
              onEdit={() => {
                /* no-op for ungrouped pseudo-group */
              }}
            />
          )}
          {groupItems.length === 0 && ungrouped.length === 0 && (
            <Card>
              <CardContent className="p-4 text-sm text-muted-foreground">
                No {KIND_LABEL[kind]} rules yet.
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </section>
  );
}

function GroupCard({
  group,
  rules,
  isAdmin,
  kindGroups,
  columnFilters,
  setColumnFilters,
  onEdit,
}: {
  group: RuleGroup | null;
  rules: Rule[];
  isAdmin: boolean;
  kindGroups: RuleGroup[];
  columnFilters: import("@/lib/table-filters").Filter[];
  setColumnFilters: (f: import("@/lib/table-filters").Filter[]) => void;
  onEdit: () => void;
}) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(true);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: () => ruleGroupsApi.remove(group!.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rule-groups"] });
      qc.invalidateQueries({ queryKey: ["rules"] });
    },
    onError: (err) => setDeleteError(err instanceof ApiError ? err.detail : String(err)),
  });

  const isUngrouped = group == null;
  const ceiling = group?.max_action ?? null;

  return (
    <Card>
      <CardHeader
        className="cursor-pointer pb-3 hover:bg-muted/30"
        onClick={() => setOpen((v) => !v)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            {open ? (
              <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
            )}
            <div className="min-w-0">
              <CardTitle className="truncate text-base">
                {isUngrouped ? (
                  <span className="text-muted-foreground">Ungrouped</span>
                ) : (
                  group!.name
                )}
              </CardTitle>
              {!isUngrouped && group!.description && (
                <p className="mt-0.5 truncate text-xs text-muted-foreground">
                  {group!.description}
                </p>
              )}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2" onClick={(e) => e.stopPropagation()}>
            <span className="text-xs text-muted-foreground">
              {rules.length} rule{rules.length === 1 ? "" : "s"}
            </span>
            {!isUngrouped && (
              <span className="inline-flex items-center gap-1 rounded-md border bg-muted/40 px-2 py-0.5 text-xs">
                max action: <RuleActionBadge action={group!.max_action} />
              </span>
            )}
            {isAdmin && !isUngrouped && (
              <>
                <Button variant="ghost" size="icon" onClick={onEdit} title="Edit group">
                  <Pencil className="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => {
                    if (
                      window.confirm(
                        `Delete group "${group!.name}"? Rules inside become ungrouped (action unclamped).`,
                      )
                    ) {
                      remove.mutate();
                    }
                  }}
                  title="Delete group"
                  disabled={remove.isPending}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </>
            )}
          </div>
        </div>
        {deleteError && (
          <div className="mt-2 rounded bg-destructive/10 px-2 py-1 text-xs text-destructive">
            {deleteError}
          </div>
        )}
      </CardHeader>
      {open && (
        <CardContent className="p-0">
          {rules.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No rules in this group.</p>
          ) : (
            <RuleRows
              rules={rules}
              ceiling={ceiling}
              kindGroups={kindGroups}
              isAdmin={isAdmin}
              columnFilters={columnFilters}
              setColumnFilters={setColumnFilters}
            />
          )}
        </CardContent>
      )}
    </Card>
  );
}

function RuleRows({
  rules,
  ceiling,
  kindGroups,
  isAdmin,
  columnFilters,
  setColumnFilters,
}: {
  rules: Rule[];
  ceiling: RuleAction | null;
  kindGroups: RuleGroup[];
  isAdmin: boolean;
  columnFilters: import("@/lib/table-filters").Filter[];
  setColumnFilters: (f: import("@/lib/table-filters").Filter[]) => void;
}) {
  const navigate = useNavigate();
  const accessorMap = new Map(RULE_COLUMNS.map((c) => [c.id, c.accessor]));
  const filteredRules =
    columnFilters.length === 0
      ? rules
      : applyFilters(rules, columnFilters, (row, col) => accessorMap.get(col)?.(row));
  const filterHead = (id: string, label: string) => (
    <th className="px-4 py-2 font-medium">
      <ColumnHeaderFilter
        colId={id}
        label={label}
        onAdd={(f) => setColumnFilters([...columnFilters, f])}
      />
    </th>
  );
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-muted/20">
          <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
            {filterHead("name", "name")}
            {filterHead("severity", "severity")}
            {filterHead("action", "action")}
            <th className="px-4 py-2 font-medium">Effective</th>
            {filterHead("enabled", "enabled")}
            <th className="px-4 py-2 font-medium">Updated</th>
            {isAdmin && <th className="px-4 py-2 font-medium">Manage</th>}
          </tr>
        </thead>
        <tbody>
          {filteredRules.length === 0 && (
            <tr>
              <td
                colSpan={isAdmin ? 7 : 6}
                className="px-4 py-3 text-center text-xs text-muted-foreground"
              >
                No rules in this group match the active filters.
              </td>
            </tr>
          )}
          {filteredRules.map((r) => {
            const eff = effectiveAction(r, ceiling);
            const clamped = eff !== r.action;
            return (
              <tr
                key={r.id}
                className="cursor-pointer border-b border-border/40 hover:bg-muted/20"
                onClick={() => navigate(`/rules/${r.id}`)}
              >
                <td className="max-w-xs px-4 py-2">
                  <div className="truncate font-medium">{r.name}</div>
                  {r.description && (
                    <div className="truncate text-xs text-muted-foreground">{r.description}</div>
                  )}
                </td>
                <td className="px-4 py-2">
                  <SeverityBadge severity={r.severity} />
                </td>
                <td className="px-4 py-2">
                  <span className={cn(clamped && "opacity-50 line-through")}>
                    <RuleActionBadge action={r.action} />
                  </span>
                </td>
                <td className="px-4 py-2">
                  {clamped ? (
                    <span className="inline-flex items-center gap-1">
                      <RuleActionBadge action={eff} />
                      <span className="text-[10px] text-muted-foreground">(clamped)</span>
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">—</span>
                  )}
                </td>
                <td className="px-4 py-2">
                  <span
                    className={cn(
                      "text-xs font-medium",
                      r.enabled ? "text-emerald-500" : "text-muted-foreground",
                    )}
                  >
                    {r.enabled ? "enabled" : "disabled"}
                  </span>
                </td>
                <td className="whitespace-nowrap px-4 py-2 text-xs text-muted-foreground">
                  {new Date(r.updated_at).toLocaleString()}
                </td>
                {isAdmin && (
                  <td className="whitespace-nowrap px-4 py-2" onClick={(e) => e.stopPropagation()}>
                    <RuleQuickActions rule={r} kindGroups={kindGroups} />
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** M22.f: per-row inline edits — enable toggle + group reassign. */
function RuleQuickActions({ rule, kindGroups }: { rule: Rule; kindGroups: RuleGroup[] }) {
  const qc = useQueryClient();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: globalThis.MouseEvent) => {
      if (!menuRef.current?.contains(e.target as globalThis.Node)) setMenuOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [menuOpen]);

  const update = useMutation({
    mutationFn: (body: Partial<{ enabled: boolean; group_id: string | null }>) => {
      // Backend uses the all-zero UUID as the "unset" sentinel on PATCH
      // since null is treated as "no change". Same trick as RuleEdit.
      const payload: Record<string, unknown> = { ...body };
      if (body.group_id === null) {
        payload.group_id = "00000000-0000-0000-0000-000000000000";
      }
      return rulesApi.update(rule.id, payload as Partial<import("@/types/api").RuleCreate>);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      qc.invalidateQueries({ queryKey: ["rule-groups"] });
    },
  });

  return (
    <div className="flex items-center gap-2">
      <Button
        size="sm"
        variant={rule.enabled ? "outline" : "secondary"}
        onClick={() => update.mutate({ enabled: !rule.enabled })}
        disabled={update.isPending}
      >
        {rule.enabled ? "Disable" : "Enable"}
      </Button>
      <div className="relative" ref={menuRef}>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setMenuOpen((v) => !v)}
          aria-label="Move to group"
        >
          <MoreHorizontal className="h-3.5 w-3.5" />
        </Button>
        {menuOpen && (
          <div className="absolute right-0 top-full z-50 mt-1 w-56 rounded-md border bg-card shadow-lg">
            <p className="border-b px-3 py-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
              Move to group
            </p>
            <ul className="max-h-72 overflow-auto">
              <li>
                <button
                  type="button"
                  className="block w-full px-3 py-1.5 text-left text-xs hover:bg-secondary/40"
                  onClick={() => {
                    update.mutate({ group_id: null });
                    setMenuOpen(false);
                  }}
                  disabled={rule.group_id == null}
                >
                  {rule.group_id == null ? "✓ " : ""}(none — ungrouped)
                </button>
              </li>
              {kindGroups.map((g) => (
                <li key={g.id}>
                  <button
                    type="button"
                    className="block w-full px-3 py-1.5 text-left text-xs hover:bg-secondary/40"
                    onClick={() => {
                      update.mutate({ group_id: g.id });
                      setMenuOpen(false);
                    }}
                    disabled={rule.group_id === g.id}
                  >
                    {rule.group_id === g.id ? "✓ " : ""}
                    {g.name} <span className="text-muted-foreground">· max {g.max_action}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
