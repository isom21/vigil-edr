import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { incidentsApi } from "@/api/incidents";
import { ApiError } from "@/api/client";
import { AlertStateBadge, SeverityBadge } from "@/components/badges";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { Alert, IncidentGroupingReason, IncidentStatus } from "@/types/api";

const STATUS_CLASS: Record<IncidentStatus, string> = {
  open: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  investigating: "bg-sev-low/15 text-sev-low border-sev-low/30",
  resolved: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  closed: "bg-muted text-muted-foreground border-border",
};

function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        STATUS_CLASS[status],
      )}
    >
      {status}
    </span>
  );
}

// Pull a candidate process pid + name off an alert's details payload.
// Producers split between `details.process` (Sigma) and
// `details.metadata.process` (IOC/anomaly); try both.
function alertProcess(alert: Alert): { pid?: number; name?: string } {
  const d = alert.details as Record<string, unknown> | null;
  if (!d) return {};
  const candidates: unknown[] = [d.process];
  if (d.metadata && typeof d.metadata === "object") {
    candidates.push((d.metadata as Record<string, unknown>).process);
  }
  for (const c of candidates) {
    if (c && typeof c === "object") {
      const proc = c as Record<string, unknown>;
      const pid = typeof proc.pid === "number" ? proc.pid : undefined;
      const name = typeof proc.name === "string" ? proc.name : undefined;
      if (pid !== undefined) return { pid, name };
    }
  }
  return {};
}

function groupingReasonLabel(reason: IncidentGroupingReason, alerts: readonly Alert[]): string {
  if (reason === "process_tree") {
    // Surface the process info from the first alert so the analyst
    // immediately sees what the grouper keyed on.
    for (const a of alerts) {
      const p = alertProcess(a);
      if (p.pid !== undefined) {
        const name = p.name ? ` ${p.name}` : "";
        return `process tree (pid ${p.pid}${name})`;
      }
    }
    return "process tree";
  }
  if (reason === "rule_cluster") return "rule cluster";
  return "time window (10min)";
}

// Allowed transitions mirror INCIDENT_STATUS_TRANSITIONS on the
// backend so the operator sees only the next-state buttons that will
// actually succeed.
const TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  open: ["investigating", "resolved", "closed"],
  investigating: ["resolved", "closed", "open"],
  resolved: ["investigating", "closed"],
  closed: [],
};

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const {
    data,
    isLoading,
    isError,
    error: loadError,
  } = useQuery({
    queryKey: ["incident", id],
    queryFn: () => incidentsApi.get(id!),
    enabled: !!id,
  });

  const changeState = useMutation({
    mutationFn: (to_state: IncidentStatus) => incidentsApi.changeState(id!, { to_state }),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["incident", id] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail : String(e)),
  });

  if (isLoading) return <div className="p-8 text-muted-foreground">Loading…</div>;
  if (isError) {
    return (
      <div className="p-8 text-destructive">
        {loadError instanceof ApiError ? loadError.detail : "Failed to load."}
      </div>
    );
  }
  if (!data) return <div className="p-8">Not found.</div>;

  const isSyntheticHost = data.host_id === null;
  const hostLabel = isSyntheticHost
    ? "System"
    : (data.host_hostname ?? data.host_id!.slice(0, 8) + "…");
  const transitions = TRANSITIONS[data.status];

  return (
    <>
      <PageHeader
        title={data.title}
        description={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span>Incident {data.id.slice(0, 8)}…</span>
            <span>·</span>
            {isSyntheticHost ? (
              <span className="italic">{hostLabel}</span>
            ) : (
              <Link to={`/hosts/${data.host_id}`} className="underline-offset-2 hover:underline">
                {hostLabel}
              </Link>
            )}
            <span>·</span>
            <span>{new Date(data.opened_at).toLocaleString()}</span>
            <span>·</span>
            <span>
              {data.alert_count} alert{data.alert_count === 1 ? "" : "s"}
            </span>
          </span>
        }
        actions={
          <div className="flex items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <IncidentStatusBadge status={data.status} />
          </div>
        }
      />
      <div className="mx-auto grid w-full max-w-[1600px] grid-cols-1 gap-6 px-6 py-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-4">
          {data.summary && (
            <div className="rounded-md border bg-card p-4 text-sm">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Summary
              </div>
              <p className="leading-relaxed">{data.summary}</p>
            </div>
          )}

          <section className="rounded-md border bg-card">
            <header className="flex items-center justify-between border-b px-4 py-3">
              <h2 className="text-sm font-semibold">Grouped alerts</h2>
              <span className="text-xs text-muted-foreground tabular-nums">
                {data.alerts.length}
              </span>
            </header>
            {data.alerts.length === 0 ? (
              <div className="p-6 text-sm text-muted-foreground">
                No alerts attached. The grouper will populate this on its next pass.
              </div>
            ) : (
              <ul className="divide-y">
                {data.alerts.map((a) => (
                  <li key={a.id} className="flex items-center gap-4 px-4 py-3">
                    <SeverityBadge severity={a.severity} />
                    <AlertStateBadge state={a.state} />
                    <Link
                      to={`/alerts/${a.id}`}
                      className="min-w-0 flex-1 truncate text-sm underline-offset-2 hover:underline"
                    >
                      {a.summary}
                    </Link>
                    <time
                      dateTime={a.opened_at}
                      className="whitespace-nowrap text-xs tabular-nums text-muted-foreground"
                    >
                      {new Date(a.opened_at).toLocaleString()}
                    </time>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        <aside className="space-y-4 lg:sticky lg:top-6 lg:self-start">
          <div className="rounded-md border bg-card p-4 text-sm">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Triage
            </div>
            {transitions.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                This incident is closed. Re-open is disabled.
              </p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {transitions.map((to) => (
                  <Button
                    key={to}
                    size="sm"
                    variant={to === "closed" ? "destructive" : "outline"}
                    onClick={() => changeState.mutate(to)}
                    disabled={changeState.isPending}
                  >
                    {changeState.isPending && changeState.variables === to
                      ? "Saving…"
                      : `Mark ${to}`}
                  </Button>
                ))}
              </div>
            )}
            {error && <div className="mt-3 text-xs text-destructive">{error}</div>}
          </div>

          <div className="rounded-md border bg-card p-4 text-xs leading-relaxed">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Metadata
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-muted-foreground">
              <dt>Opened</dt>
              <dd className="text-foreground">{new Date(data.opened_at).toLocaleString()}</dd>
              {data.closed_at && (
                <>
                  <dt>Closed</dt>
                  <dd className="text-foreground">{new Date(data.closed_at).toLocaleString()}</dd>
                </>
              )}
              <dt>Updated</dt>
              <dd className="text-foreground">{new Date(data.updated_at).toLocaleString()}</dd>
              <dt>Grouped by</dt>
              <dd className="text-foreground">
                {groupingReasonLabel(data.grouping_reason, data.alerts)}
              </dd>
              {data.assignee_id && (
                <>
                  <dt>Assignee</dt>
                  <dd className="font-mono text-foreground">{data.assignee_id.slice(0, 8)}…</dd>
                </>
              )}
            </dl>
          </div>
        </aside>
      </div>
    </>
  );
}
