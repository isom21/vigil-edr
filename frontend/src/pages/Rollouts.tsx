/**
 * Rollouts dashboard (Phase 3 #3.3).
 *
 * Per-policy view of agent rollout cohorts: target version, current
 * roll-out percentage, success/failed/in-flight counts per cohort, and
 * the last week's worth of rollout activity as a sparkline. Admins can
 * advance the percentage from this page; analysts get a read-only view.
 *
 * The auto-rollback breaker lives in the backend's `rollout_monitor`
 * worker — if a cohort accumulates `VIGIL_ROLLOUT_FAILURE_THRESHOLD`
 * failures within `VIGIL_ROLLOUT_FAILURE_WINDOW_S`, the policy's
 * percentage is slammed to 0 and a critical alert is emitted. This
 * page just surfaces the state; it never trips the breaker itself.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError } from "@/api/client";
import { rolloutsApi } from "@/api/rollouts";
import { ChartCard } from "@/components/charts/ChartCard";
import { Sparkline, type SparkPoint } from "@/components/charts/Sparkline";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/hooks/useAuth";
import type { PolicyRolloutOut, RolloutEvent } from "@/types/api";

const DAY_MS = 24 * 60 * 60 * 1000;
const WINDOW_DAYS = 7;

/** Bucket the recent events into per-day counts spanning the last 7d. */
function buildSparkline(events: RolloutEvent[]): SparkPoint[] {
  const now = Date.now();
  const buckets: SparkPoint[] = [];
  for (let i = WINDOW_DAYS - 1; i >= 0; i--) {
    const day = new Date(now - i * DAY_MS);
    day.setUTCHours(0, 0, 0, 0);
    buckets.push({ ts: day.toISOString().slice(0, 10), count: 0 });
  }
  for (const e of events) {
    const ts = new Date(e.started_at).getTime();
    const diff = Math.floor((now - ts) / DAY_MS);
    if (diff < 0 || diff >= WINDOW_DAYS) continue;
    const idx = WINDOW_DAYS - 1 - diff;
    buckets[idx].count += 1;
  }
  return buckets;
}

function CohortRow({ policy }: { policy: PolicyRolloutOut }) {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [draftPct, setDraftPct] = useState<string>(String(policy.cohort_rolled_out_pct));
  const [error, setError] = useState<string | null>(null);

  const advance = useMutation({
    mutationFn: (toPct: number) => rolloutsApi.advance(policy.policy_id, toPct),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rollouts"] });
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const sparkline = useMemo(() => buildSparkline(policy.recent), [policy.recent]);

  const totals = policy.cohorts.reduce(
    (acc, c) => {
      acc.success += c.success;
      acc.failed += c.failed;
      acc.in_flight += c.in_flight;
      return acc;
    },
    { success: 0, failed: 0, in_flight: 0 },
  );

  const halted = policy.cohort_rolled_out_pct === 0 && totals.failed > 0;

  function onAdvance() {
    const n = Number.parseInt(draftPct, 10);
    if (Number.isNaN(n) || n < 0 || n > 100) {
      setError("percentage must be 0–100");
      return;
    }
    advance.mutate(n);
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-baseline justify-between space-y-0">
        <div>
          <CardTitle className="text-base">{policy.policy_name}</CardTitle>
          <p className="text-xs text-muted-foreground">
            target: {policy.cohort_target_version ?? "—"}
            {policy.rollout_cohort ? ` · cohort: ${policy.rollout_cohort}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={
              halted
                ? "rounded-md bg-destructive/10 px-2 py-1 text-xs font-medium text-destructive"
                : "rounded-md bg-muted px-2 py-1 text-xs font-medium tabular-nums"
            }
          >
            {policy.cohort_rolled_out_pct}% rolled out{halted ? " · HALTED" : ""}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {policy.cohorts.map((c) => (
            <div key={c.cohort} className="rounded-md border p-3">
              <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                {c.cohort}
              </div>
              <div className="mt-1 flex gap-4 text-sm tabular-nums">
                <span className="text-emerald-600">{c.success} ok</span>
                <span className="text-destructive">{c.failed} failed</span>
                <span className="text-muted-foreground">{c.in_flight} in-flight</span>
              </div>
            </div>
          ))}
        </div>
        <ChartCard title="Last 7 days" hint="Per-day rollout events">
          <Sparkline data={sparkline} height={48} width={320} showAxis />
        </ChartCard>
        {isAdmin && (
          <div className="flex items-center gap-2">
            <Input
              type="number"
              min={0}
              max={100}
              value={draftPct}
              onChange={(e) => setDraftPct(e.target.value)}
              className="w-24"
              aria-label={`advance ${policy.policy_name} to percentage`}
            />
            <Button
              size="sm"
              onClick={onAdvance}
              disabled={advance.isPending || draftPct === String(policy.cohort_rolled_out_pct)}
            >
              Advance
            </Button>
            {error && <span className="text-xs text-destructive">{error}</span>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function Rollouts() {
  const list = useQuery({
    queryKey: ["rollouts"],
    queryFn: () => rolloutsApi.list(),
    refetchInterval: 15_000,
  });

  return (
    <>
      <PageHeader
        title="Rollouts"
        description="Per-policy agent rollout cohorts. Failures within the configured window auto-halt the rollout."
      />
      <div className="space-y-4 px-8 py-6">
        {list.isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
        {list.error && (
          <div className="text-sm text-destructive">
            Failed to load rollouts:{" "}
            {list.error instanceof ApiError ? list.error.detail : String(list.error)}
          </div>
        )}
        {list.data?.length === 0 && (
          <div className="text-sm text-muted-foreground">
            No policies configured. Create one under Detection · Rules to schedule a rollout.
          </div>
        )}
        {list.data?.map((p) => (
          <CohortRow key={p.policy_id} policy={p} />
        ))}
      </div>
    </>
  );
}
