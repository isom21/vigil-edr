/**
 * M20.d/f: alert investigation page tabs.
 *
 * Two top-level tabs hydrate from `GET /api/alerts/:id/context`:
 *   - Process chain: ancestry walk back from the triggering event.
 *   - Event log:     ±window_minutes of host telemetry around opened_at.
 *
 * Triage UX lives in a sibling rail rendered by AlertDetail; this
 * component is purely the analyst's investigation surface.
 */
import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { ColumnHeaderFilter } from "@/components/data-table/ColumnHeaderFilter";
import { FilterChipBar } from "@/components/data-table/FilterChipBar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { applyFilters, useColumnFilters } from "@/lib/table-filters";
import { cn } from "@/lib/utils";
import type { ProcessChainNode, TimelineEvent } from "@/types/api";

const TIMELINE_COLUMNS: { id: string; label: string; accessor: (e: TimelineEvent) => unknown }[] = [
  { id: "time", label: "time", accessor: (e) => e.timestamp },
  { id: "action", label: "action", accessor: (e) => e.action ?? "" },
  { id: "pid", label: "pid", accessor: (e) => e.pid ?? "" },
  {
    id: "target",
    label: "target",
    accessor: (e) => e.file_path ?? e.destination_ip ?? e.executable ?? e.command_line ?? "",
  },
];
const TIMELINE_LABELS = Object.fromEntries(TIMELINE_COLUMNS.map((c) => [c.id, c.label]));

interface Props {
  alertId: string;
}

export function AlertInvestigation({ alertId }: Props) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["alert-context", alertId],
    queryFn: () => alertsApi.context(alertId, { window_minutes: 15 }),
  });

  if (isLoading) {
    return <div className="p-6 text-sm text-muted-foreground">Loading investigation context…</div>;
  }
  if (isError) {
    return (
      <div className="p-6 text-sm text-destructive">
        {error instanceof ApiError ? error.detail : "Failed to load context."}
      </div>
    );
  }
  if (!data) return null;

  return (
    <Tabs defaultValue="chain" className="w-full">
      <TabsList>
        <TabsTrigger value="chain">Process chain ({data.chain.length})</TabsTrigger>
        <TabsTrigger value="events">
          Event log ±15 min ({data.events.length}
          {data.events_truncated ? "+" : ""})
        </TabsTrigger>
      </TabsList>
      <TabsContent value="chain">
        <ProcessChainPanel alertId={alertId} chain={data.chain} hostId={data.host_id} />
      </TabsContent>
      <TabsContent value="events">
        <TimelinePanel
          events={data.events}
          windowStart={data.window_start}
          windowEnd={data.window_end}
          truncated={data.events_truncated}
          openedAt={data.opened_at}
        />
      </TabsContent>
    </Tabs>
  );
}

function ProcessChainPanel({
  alertId,
  chain,
  hostId,
}: {
  alertId: string;
  chain: ProcessChainNode[];
  hostId: string;
}) {
  // M20.i: clicking a chain node pivots the bottom detail panel to that
  // pid. Default selection = the triggering process (depth 0). We use
  // index, not pid, because the same pid could theoretically appear
  // twice (cycle short-circuited by `seen` server-side, but defensive).
  const [selectedIdx, setSelectedIdx] = useState(0);
  // Selection target — either a chain node by index or a sibling pid.
  // Kept separate so flipping back to a chain node restores the
  // highlight cleanly. Hoisted above the early-return guard so the
  // hook order stays stable across renders.
  const [selectedSiblingPid, setSelectedSiblingPid] = useState<number | null>(null);
  // Reset selection whenever the chain shape changes (alert switched).
  useEffect(() => {
    setSelectedIdx(0);
    setSelectedSiblingPid(null);
  }, [alertId, chain.length]);

  if (chain.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          No process telemetry was recorded for this alert's triggering event.
        </CardContent>
      </Card>
    );
  }

  const selectedNode =
    selectedSiblingPid != null
      ? (chain.flatMap((n) => n.siblings).find((s) => s.pid === selectedSiblingPid) ??
        chain[selectedIdx])
      : (chain[selectedIdx] ?? chain[0]);

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        {chain.map((node, i) => (
          <ProcessChainCard
            key={`${node.pid}-${i}`}
            node={node}
            depth={i}
            hostId={hostId}
            isLeaf={i === chain.length - 1}
            isSelected={selectedSiblingPid == null && i === selectedIdx}
            onSelect={() => {
              setSelectedIdx(i);
              setSelectedSiblingPid(null);
            }}
            selectedSiblingPid={selectedSiblingPid}
            onSelectSibling={(pid) => setSelectedSiblingPid(pid)}
          />
        ))}
      </div>
      {selectedNode && !selectedNode.inferred && selectedNode.pid > 0 && (
        <SelectedProcessDetail alertId={alertId} pid={selectedNode.pid} />
      )}
    </div>
  );
}

function ProcessChainCard({
  node,
  depth,
  hostId,
  isLeaf,
  isSelected,
  onSelect,
  selectedSiblingPid,
  onSelectSibling,
}: {
  node: ProcessChainNode;
  depth: number;
  hostId: string;
  isLeaf: boolean;
  isSelected: boolean;
  onSelect: () => void;
  selectedSiblingPid?: number | null;
  onSelectSibling?: (pid: number) => void;
}) {
  const [showSiblings, setShowSiblings] = useState(false);
  const selectable = !node.inferred && node.pid > 0;
  const siblings = node.siblings ?? [];
  return (
    <Card
      className={cn(
        node.inferred && "opacity-60",
        selectable &&
          "cursor-pointer hover:border-foreground/30 focus-visible:border-sev-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        isSelected && "border-sev-medium bg-sev-medium/5",
      )}
      onClick={() => selectable && onSelect()}
      onKeyDown={(e) => {
        if (!selectable) return;
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect();
        }
      }}
      role={selectable ? "button" : undefined}
      tabIndex={selectable ? 0 : undefined}
      aria-pressed={selectable ? isSelected : undefined}
    >
      <CardHeader className="flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-mono">
          {depth === 0 ? "triggered" : `parent +${depth}`} · pid {node.pid}
          {node.name && <span className="text-muted-foreground"> · {node.name}</span>}
        </CardTitle>
        <div className="flex items-center gap-2">
          {node.integrity_level && (
            <span className="rounded-md border bg-muted/40 px-2 py-0.5 text-xs">
              {node.integrity_level}
            </span>
          )}
          {!isLeaf && <span className="text-xs text-muted-foreground">↓ spawned</span>}
          {selectable && (
            <span
              className={cn(
                "rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
                isSelected
                  ? "border-sev-medium text-sev-medium"
                  : "border-border text-muted-foreground",
              )}
            >
              {isSelected ? "selected" : "click to inspect"}
            </span>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-1 pt-0 text-xs">
        {node.inferred ? (
          <p className="text-muted-foreground">
            No process_started telemetry recorded for pid {node.pid} — process predates the lookback
            window or was never observed.
          </p>
        ) : (
          <>
            <Row label="executable" value={node.executable} mono />
            <Row label="command line" value={node.command_line} mono wrap />
            <Row label="sha256" value={node.sha256} mono />
            <Row label="user" value={node.user_name} />
            <Row label="cwd" value={node.working_directory} mono />
            <Row
              label="started"
              value={node.started_at ? new Date(node.started_at).toLocaleString() : null}
            />
            <Row
              label="parent pid"
              value={node.parent_pid != null ? String(node.parent_pid) : null}
            />
          </>
        )}
        <div className="flex items-center justify-between pt-1 text-xs">
          <Link
            to={`/hosts/${hostId}`}
            className="text-muted-foreground underline decoration-dotted underline-offset-2 hover:text-foreground"
            onClick={(e) => e.stopPropagation()}
          >
            view host
          </Link>
          {siblings.length > 0 && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setShowSiblings((v) => !v);
              }}
              className="text-muted-foreground underline decoration-dotted underline-offset-2 hover:text-foreground"
            >
              {showSiblings ? "hide" : "show"} {siblings.length} sibling
              {siblings.length === 1 ? "" : "s"}
            </button>
          )}
        </div>
        {showSiblings && siblings.length > 0 && (
          <div
            className="mt-2 space-y-1 border-l border-border/40 pl-3"
            onClick={(e) => e.stopPropagation()}
          >
            {siblings.map((sib, sibIdx) => {
              const isSibSelected = selectedSiblingPid === sib.pid;
              return (
                <button
                  key={`${sib.pid}-${sibIdx}`}
                  type="button"
                  onClick={() => onSelectSibling?.(sib.pid)}
                  className={cn(
                    "block w-full rounded border px-2 py-1 text-left font-mono text-[11px]",
                    isSibSelected
                      ? "border-sev-medium bg-sev-medium/5 text-foreground"
                      : "border-border/60 text-muted-foreground hover:border-foreground/30 hover:text-foreground",
                  )}
                >
                  <span>pid {sib.pid}</span>
                  {sib.name && <span className="ml-2 text-muted-foreground">· {sib.name}</span>}
                  {sib.executable && (
                    <span className="ml-2 truncate text-muted-foreground/70">{sib.executable}</span>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SelectedProcessDetail({ alertId, pid }: { alertId: string; pid: number }) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["alert-context", alertId, "process", pid],
    queryFn: () => alertsApi.processDetail(alertId, pid, { window_minutes: 15 }),
  });

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">
          What pid {pid} did during the alert window
          {data && (
            <span className="ml-2 text-muted-foreground">
              (
              {data.image_loads.length +
                data.files.length +
                data.network.length +
                data.other.length}{" "}
              events
              {data.truncated ? "+" : ""})
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 pt-0 text-xs">
        {isLoading && <p className="text-muted-foreground">Loading…</p>}
        {isError && (
          <p className="text-destructive">
            {error instanceof ApiError ? error.detail : "Failed to load process detail."}
          </p>
        )}
        {data && (
          <>
            <DetailGroup
              label="Image loads"
              count={data.image_loads.length}
              empty="No DLL / shared-library loads recorded."
            >
              {data.image_loads.length > 0 && (
                <SimpleTable
                  cols={["time", "path", "sha256", "signer"]}
                  rows={data.image_loads.map((il) => [
                    fmtTimeShort(il.timestamp),
                    il.path ?? "—",
                    il.sha256 ? il.sha256.slice(0, 12) + "…" : "—",
                    il.signed === false ? "unsigned" : (il.signer ?? "—"),
                  ])}
                />
              )}
            </DetailGroup>
            <DetailGroup
              label="File activity"
              count={data.files.length}
              empty="No file events from this pid."
            >
              {data.files.length > 0 && (
                <SimpleTable
                  cols={["time", "action", "path", "sha256"]}
                  rows={data.files.map((f) => [
                    fmtTimeShort(f.timestamp),
                    f.action ?? "—",
                    f.target_path ? `${f.path ?? "—"} → ${f.target_path}` : (f.path ?? "—"),
                    f.sha256 ? f.sha256.slice(0, 12) + "…" : "—",
                  ])}
                />
              )}
            </DetailGroup>
            <DetailGroup
              label="Network"
              count={data.network.length}
              empty="No network activity from this pid."
            >
              {data.network.length > 0 && (
                <SimpleTable
                  cols={["time", "action", "transport", "destination"]}
                  rows={data.network.map((n) => [
                    fmtTimeShort(n.timestamp),
                    n.action ?? "—",
                    n.transport ?? "—",
                    n.destination_ip
                      ? n.destination_port
                        ? `${n.destination_ip}:${n.destination_port}`
                        : n.destination_ip
                      : "—",
                  ])}
                />
              )}
            </DetailGroup>
            {data.other.length > 0 && (
              <DetailGroup label="Other" count={data.other.length} empty="">
                <SimpleTable
                  cols={["time", "category", "action"]}
                  rows={data.other.map((o) => [
                    fmtTimeShort(o.timestamp),
                    o.category.join(",") || "—",
                    o.action ?? "—",
                  ])}
                />
              </DetailGroup>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function DetailGroup({
  label,
  count,
  empty,
  children,
}: {
  label: string;
  count: number;
  empty: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div className="mb-1 flex items-center gap-2 text-xs font-medium text-muted-foreground">
        <span>{label}</span>
        <span className="text-[10px]">({count})</span>
      </div>
      {count === 0 ? <p className="text-xs text-muted-foreground/70">{empty}</p> : children}
    </div>
  );
}

function SimpleTable({ cols, rows }: { cols: string[]; rows: (string | number)[][] }) {
  // Cap rendering so a noisy process doesn't lock up the page; the
  // backend already truncates at 1000 events.
  const MAX = 100;
  const visible = rows.slice(0, MAX);
  return (
    <div className="overflow-auto rounded border">
      <table className="w-full text-[11px]">
        <thead className="bg-muted/30">
          <tr>
            {cols.map((c) => (
              <th key={c} className="px-2 py-1 text-left font-medium text-muted-foreground">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {visible.map((r, i) => (
            <tr key={i} className="border-t border-border/40 align-top font-mono">
              {r.map((cell, j) => (
                <td key={j} className="px-2 py-1 break-all">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > MAX && (
        <p className="bg-muted/20 px-2 py-1 text-[10px] text-muted-foreground">
          showing first {MAX} of {rows.length}
        </p>
      )}
    </div>
  );
}

function fmtTimeShort(iso: string): string {
  return new Date(iso).toLocaleTimeString();
}

function TimelinePanel({
  events,
  windowStart,
  windowEnd,
  truncated,
  openedAt,
}: {
  events: TimelineEvent[];
  windowStart: string;
  windowEnd: string;
  truncated: boolean;
  openedAt: string;
}) {
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();
  const accessorMap = useMemo(() => new Map(TIMELINE_COLUMNS.map((c) => [c.id, c.accessor])), []);
  const filteredEvents = useMemo(() => {
    if (columnFilters.length === 0) return events;
    return applyFilters(events, columnFilters, (row, col) => accessorMap.get(col)?.(row));
  }, [events, columnFilters, accessorMap]);
  if (events.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          No telemetry recorded for this host between {fmt(windowStart)} and {fmt(windowEnd)}.
        </CardContent>
      </Card>
    );
  }
  const opened = new Date(openedAt).getTime();
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">
          {fmt(windowStart)} → {fmt(windowEnd)}{" "}
          <span className="text-muted-foreground">
            ({filteredEvents.length}
            {columnFilters.length > 0 ? ` of ${events.length}` : ""} events)
          </span>
        </CardTitle>
        {truncated && (
          <p className="text-xs text-amber-500">
            Truncated to first {events.length} events — narrow the window to see more.
          </p>
        )}
        <div className="mt-2">
          <FilterChipBar
            tableId="alert-timeline"
            filters={columnFilters}
            columnLabels={TIMELINE_LABELS}
            onRemove={(i) => setColumnFilters(columnFilters.filter((_, j) => j !== i))}
            onClear={() => setColumnFilters([])}
            onApply={setColumnFilters}
          />
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="max-h-[600px] overflow-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card">
              <tr className="border-b">
                {TIMELINE_COLUMNS.map((c) => (
                  <th key={c.id} className="px-3 py-2 text-left font-medium text-muted-foreground">
                    <ColumnHeaderFilter
                      colId={c.id}
                      label={c.label}
                      onAdd={(f) => setColumnFilters([...columnFilters, f])}
                    />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((e) => (
                <tr
                  key={e.event_id}
                  className={cn(
                    "border-b border-border/40 align-top",
                    e.is_trigger && "bg-sev-medium/10",
                  )}
                >
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-muted-foreground">
                    {fmtTime(e.timestamp, opened)}
                  </td>
                  <td className="px-3 py-1.5 font-mono">
                    {e.action ?? "—"}
                    {e.outcome === "failure" && <span className="ml-1 text-sev-critical">✕</span>}
                    {e.is_trigger && (
                      <span className="ml-1 rounded bg-sev-medium/30 px-1 text-[10px] uppercase text-sev-medium">
                        trigger
                      </span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-muted-foreground">
                    {e.pid ?? "—"}
                  </td>
                  <td className="px-3 py-1.5 font-mono break-all text-muted-foreground">
                    {targetDescription(e)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

function targetDescription(e: TimelineEvent): string {
  if (e.file_path) return e.file_path;
  if (e.destination_ip) {
    const port = e.destination_port ? `:${e.destination_port}` : "";
    return `${e.destination_ip}${port}`;
  }
  if (e.executable) return e.executable;
  if (e.command_line) return e.command_line;
  return "—";
}

function Row({
  label,
  value,
  mono,
  wrap,
}: {
  label: string;
  value: string | null | undefined;
  mono?: boolean;
  wrap?: boolean;
}) {
  if (!value) {
    return (
      <div className="flex gap-2">
        <span className="w-28 shrink-0 text-muted-foreground">{label}</span>
        <span className="text-muted-foreground/60">—</span>
      </div>
    );
  }
  return (
    <div className="flex gap-2">
      <span className="w-28 shrink-0 text-muted-foreground">{label}</span>
      <span
        className={cn(
          mono && "font-mono",
          wrap ? "break-all" : "truncate",
          "min-w-0 flex-1 text-foreground",
        )}
      >
        {value}
      </span>
    </div>
  );
}

function fmt(iso: string): string {
  return new Date(iso).toLocaleString();
}

function fmtTime(iso: string, openedAtMs: number): string {
  const d = new Date(iso);
  const ms = d.getTime() - openedAtMs;
  const sign = ms >= 0 ? "+" : "−";
  const abs = Math.abs(Math.round(ms / 1000));
  const m = Math.floor(abs / 60);
  const s = abs % 60;
  return `${d.toLocaleTimeString()} (${sign}${m}m${s.toString().padStart(2, "0")}s)`;
}
