/**
 * Playbook run history (Phase 3 #3.5).
 *
 * One row per run, expandable to show the per-step timeline read from
 * `steps_executed_json`. Each step records its kind, outcome (ok /
 * skipped / failed), start + finish timestamps, and any kind-specific
 * details (command_id, channel_id, error message).
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ChevronDown, ChevronRight } from "lucide-react";

import { playbooksApi } from "@/api/playbooks";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { PlaybookRun, PlaybookRunStatus, PlaybookStep } from "@/types/api";

const STATUS_LABEL: Record<PlaybookRunStatus, string> = {
  pending: "Pending",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
  partial: "Partial",
};

const STATUS_TONE: Record<PlaybookRunStatus, string> = {
  pending: "bg-muted text-muted-foreground",
  running: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  succeeded: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  failed: "bg-destructive/15 text-destructive",
  partial: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
};

const OUTCOME_TONE: Record<string, string> = {
  ok: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  skipped: "bg-muted text-muted-foreground",
  failed: "bg-destructive/15 text-destructive",
};

export function PlaybookRuns() {
  const { id } = useParams<{ id: string }>();
  const playbookId = id ?? "";

  const playbookQ = useQuery({
    queryKey: ["playbook", playbookId],
    queryFn: () => playbooksApi.get(playbookId),
    enabled: Boolean(playbookId),
  });

  const runsQ = useQuery({
    queryKey: ["playbook-runs", playbookId],
    queryFn: () => playbooksApi.listRuns(playbookId, { limit: 200 }),
    enabled: Boolean(playbookId),
    refetchInterval: 10_000,
  });

  return (
    <>
      <PageHeader
        title={playbookQ.data ? `Runs · ${playbookQ.data.name}` : "Playbook runs"}
        description={
          <span>
            One row per fire. Click a run to expand its step timeline. The list refreshes every 10
            seconds while you're on this page.{" "}
            <Link to="/playbooks" className="underline">
              Back to playbooks
            </Link>
          </span>
        }
      />
      <div className="p-8">
        <Card>
          <CardHeader>
            <CardTitle>Run history</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Started</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Steps</TableHead>
                  <TableHead>Alert</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runsQ.isLoading && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-muted-foreground">
                      Loading…
                    </TableCell>
                  </TableRow>
                )}
                {runsQ.data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-muted-foreground">
                      No runs yet. Runs land here when an alert matches one of this playbook's
                      triggers.
                    </TableCell>
                  </TableRow>
                )}
                {runsQ.data?.items.map((run) => (
                  <RunRow key={run.id} run={run} />
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function RunRow({ run }: { run: PlaybookRun }) {
  const [open, setOpen] = useState(false);
  const steps = run.steps_executed_json ?? [];
  return (
    <>
      <TableRow className="cursor-pointer" onClick={() => setOpen((v) => !v)}>
        <TableCell>
          {open ? (
            <ChevronDown className="h-4 w-4" aria-hidden="true" />
          ) : (
            <ChevronRight className="h-4 w-4" aria-hidden="true" />
          )}
        </TableCell>
        <TableCell className="font-mono text-xs">{formatTs(run.started_at)}</TableCell>
        <TableCell>
          <Badge className={cn("text-xs uppercase", STATUS_TONE[run.status])}>
            {STATUS_LABEL[run.status]}
          </Badge>
        </TableCell>
        <TableCell className="text-right text-xs tabular-nums">{steps.length}</TableCell>
        <TableCell className="font-mono text-xs">
          {run.alert_id ? (
            <Link to={`/alerts/${run.alert_id}`} className="underline">
              {run.alert_id.slice(0, 8)}…
            </Link>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </TableCell>
      </TableRow>
      {open && (
        <TableRow>
          <TableCell colSpan={5}>
            <StepTimeline steps={steps} error={run.error} />
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

function StepTimeline({ steps, error }: { steps: PlaybookStep[]; error: string | null }) {
  if (steps.length === 0 && !error) {
    return <p className="text-xs text-muted-foreground">No steps recorded for this run.</p>;
  }
  return (
    <div className="space-y-2 py-2">
      {error && (
        <div className="rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
          Run-level error: {error}
        </div>
      )}
      <ol className="space-y-2">
        {steps.map((s, idx) => (
          <li
            key={idx}
            className="rounded-md border bg-muted/30 p-3 text-xs"
            aria-label={`Step ${idx + 1}: ${s.kind}`}
          >
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] text-muted-foreground">#{idx + 1}</span>
              <span className="font-semibold">{s.kind}</span>
              <Badge className={cn("text-[10px] uppercase", OUTCOME_TONE[s.outcome])}>
                {s.outcome}
              </Badge>
              <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                {formatTs(s.started_at)}
              </span>
            </div>
            <StepDetails step={s} />
          </li>
        ))}
      </ol>
    </div>
  );
}

function StepDetails({ step }: { step: PlaybookStep }) {
  const details: { label: string; value: string }[] = [];
  if (typeof step.error === "string") details.push({ label: "error", value: step.error });
  if (typeof step.reason === "string") details.push({ label: "reason", value: step.reason });
  if (typeof step.command_id === "string")
    details.push({ label: "command", value: step.command_id });
  if (typeof step.channel_id === "string")
    details.push({ label: "channel", value: step.channel_id });
  if (typeof step.truthy === "boolean")
    details.push({ label: "truthy", value: String(step.truthy) });
  if (typeof step.skipped_next === "boolean")
    details.push({ label: "skipped_next", value: String(step.skipped_next) });
  if (details.length === 0) return null;
  return (
    <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-[11px]">
      {details.map((d) => (
        <div key={d.label} className="contents">
          <dt className="font-mono text-muted-foreground">{d.label}</dt>
          <dd className="break-all font-mono">{d.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function formatTs(ts: string | null | undefined): string {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}
