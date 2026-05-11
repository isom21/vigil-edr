/**
 * M20.d: alert investigation tabs.
 *
 * Two sub-tabs hydrate from `GET /api/alerts/:id/context`:
 *   - Process chain: ancestry walk back from the triggering event.
 *   - Timeline:      ±window_minutes of host telemetry around opened_at.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import type { ProcessChainNode, TimelineEvent } from "@/types/api";

interface Props {
  alertId: string;
}

export function AlertInvestigation({ alertId }: Props) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["alert-context", alertId],
    queryFn: () => alertsApi.context(alertId, { window_minutes: 15 }),
  });

  if (isLoading) {
    return <div className="p-6 text-sm text-muted-foreground">loading investigation context…</div>;
  }
  if (isError) {
    return (
      <div className="p-6 text-sm text-destructive">
        {error instanceof ApiError ? error.detail : "failed to load context"}
      </div>
    );
  }
  if (!data) return null;

  return (
    <Tabs defaultValue="chain" className="w-full">
      <TabsList>
        <TabsTrigger value="chain">Process chain ({data.chain.length})</TabsTrigger>
        <TabsTrigger value="timeline">
          Timeline ({data.events.length}
          {data.events_truncated ? "+" : ""})
        </TabsTrigger>
      </TabsList>
      <TabsContent value="chain">
        <ProcessChainPanel chain={data.chain} hostId={data.host_id} />
      </TabsContent>
      <TabsContent value="timeline">
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

function ProcessChainPanel({ chain, hostId }: { chain: ProcessChainNode[]; hostId: string }) {
  if (chain.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          No process telemetry was recorded for this alert's triggering event.
        </CardContent>
      </Card>
    );
  }
  return (
    <div className="space-y-2">
      {chain.map((node, i) => (
        <ProcessChainCard
          key={`${node.pid}-${i}`}
          node={node}
          depth={i}
          hostId={hostId}
          isLeaf={i === chain.length - 1}
        />
      ))}
    </div>
  );
}

function ProcessChainCard({
  node,
  depth,
  hostId,
  isLeaf,
}: {
  node: ProcessChainNode;
  depth: number;
  hostId: string;
  isLeaf: boolean;
}) {
  return (
    <Card className={cn(node.inferred && "opacity-60")}>
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
        <div className="pt-1 text-xs">
          <Link
            to={`/hosts/${hostId}`}
            className="text-muted-foreground underline decoration-dotted underline-offset-2 hover:text-foreground"
          >
            view host
          </Link>
        </div>
      </CardContent>
    </Card>
  );
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
          <span className="text-muted-foreground">({events.length} events)</span>
        </CardTitle>
        {truncated && (
          <p className="text-xs text-amber-500">
            Truncated to first {events.length} events — narrow the window to see more.
          </p>
        )}
      </CardHeader>
      <CardContent className="p-0">
        <div className="max-h-[600px] overflow-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card">
              <tr className="border-b">
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">time</th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">action</th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">pid</th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">target</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
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
