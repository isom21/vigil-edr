import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { AlertStateBadge, SeverityBadge } from "@/components/badges";
import { AlertDetailPanel } from "@/components/AlertDetailPanel";
import { AlertInvestigation } from "@/components/AlertInvestigation";
import { PageHeader } from "@/components/PageHeader";
import { ProcessGraph } from "@/components/ProcessGraph";
import { AiSummaryWidget } from "@/components/widgets/AiSummaryWidget";
import type { CaseSyncState } from "@/types/api";

const CASE_STATE_CLASS: Record<CaseSyncState, string> = {
  open: "text-sky-500",
  in_progress: "text-amber-500",
  resolved: "text-emerald-500",
  closed: "text-muted-foreground",
  failed: "text-destructive",
};

export function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["alert", id],
    queryFn: () => alertsApi.get(id!),
    enabled: !!id,
  });

  if (isLoading) return <div className="p-8 text-muted-foreground">Loading…</div>;
  if (isError) {
    return (
      <div className="p-8 text-destructive">
        {error instanceof ApiError ? error.detail : "Failed to load."}
      </div>
    );
  }
  if (!data) return <div className="p-8">Not found.</div>;

  // Synthetic alerts (audit chain break, etc.) have host_id=null.
  // Render as plain "System" label instead of a host link.
  const isSynthetic = data.host_id === null;
  const hostLabel = isSynthetic
    ? "System"
    : (data.host_hostname ?? data.host_id!.slice(0, 8) + "…");
  const ruleLabel = data.rule_name ?? data.rule_id.slice(0, 8) + "…";
  // Phase 1 #1.10: when this alert has folded in re-detonations, show
  // an "x N · last seen <time>" badge in the header so analysts know
  // they're looking at a recurring signal rather than a one-off.
  const deduped = data.occurrence_count > 1;

  return (
    <>
      <PageHeader
        title={data.summary}
        description={
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span>Alert {data.id.slice(0, 8)}…</span>
            <span>·</span>
            {isSynthetic ? (
              <span className="italic">{hostLabel}</span>
            ) : (
              <Link to={`/hosts/${data.host_id}`} className="underline-offset-2 hover:underline">
                {hostLabel}
              </Link>
            )}
            <span>·</span>
            <Link to={`/rules/${data.rule_id}`} className="underline-offset-2 hover:underline">
              {ruleLabel}
            </Link>
            <span>·</span>
            <span>{new Date(data.opened_at).toLocaleString()}</span>
            {deduped && (
              <>
                <span>·</span>
                <span
                  className="rounded-full border bg-muted px-2 py-0.5 font-mono text-[11px] tabular-nums text-foreground"
                  title={`Last detection at ${new Date(data.last_occurred_at).toLocaleString()}`}
                >
                  seen ×{data.occurrence_count} · last{" "}
                  {new Date(data.last_occurred_at).toLocaleString()}
                </span>
              </>
            )}
            {data.mitre_techniques && data.mitre_techniques.length > 0 ? (
              <>
                <span>·</span>
                <span className="flex flex-wrap items-center gap-1">
                  {data.mitre_techniques.map((t) => (
                    <a
                      key={t}
                      href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center rounded-md border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-foreground hover:bg-muted"
                      title={`ATT&CK ${t} — opens in a new tab`}
                    >
                      {t}
                    </a>
                  ))}
                </span>
              </>
            ) : null}
          </div>
        }
        actions={
          <div className="flex items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <AlertStateBadge state={data.state} />
          </div>
        }
      />
      {/* Phase 3 #3.6: linked external cases. Sits between the header
          and the investigation grid so analysts see the mirror status
          at a glance without scrolling the triage rail. */}
      {data.case_links && data.case_links.length > 0 ? (
        <div className="mx-auto w-full max-w-[1600px] px-6 pt-4">
          <div className="flex flex-wrap items-center gap-3 rounded-md border bg-muted/40 px-3 py-2 text-xs">
            <span className="font-medium uppercase tracking-wider text-muted-foreground">
              Linked cases
            </span>
            {data.case_links.map((link) => (
              <span key={link.destination_id} className="flex items-center gap-1.5">
                <span className="text-muted-foreground">{link.destination_name}</span>
                {link.external_url ? (
                  <a
                    href={link.external_url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-0.5 font-mono underline-offset-2 hover:underline"
                    title={`Open ${link.external_id} in tracker`}
                  >
                    {link.external_id || "—"}
                    <ExternalLink className="h-3 w-3" aria-hidden="true" />
                  </a>
                ) : (
                  <span className="font-mono text-muted-foreground">{link.external_id || "—"}</span>
                )}
                <span
                  className={`text-[10px] uppercase tracking-wider ${
                    CASE_STATE_CLASS[link.sync_state]
                  }`}
                >
                  {link.sync_state.replace("_", " ")}
                </span>
                {link.error ? (
                  <span className="text-destructive" title={link.error}>
                    (error)
                  </span>
                ) : null}
              </span>
            ))}
          </div>
        </div>
      ) : null}
      {/* Two-column investigation layout:
            main column   = process chain + event log (the two tabs)
            triage rail   = state transitions, response actions, history */}
      <div className="mx-auto grid w-full max-w-[1600px] grid-cols-1 gap-6 px-6 py-6 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-w-0">
          {isSynthetic ? (
            <div className="rounded-md border border-dashed bg-muted/30 p-6 text-sm text-muted-foreground">
              No host telemetry to investigate — this is a manager-internal alert. See the alert
              details panel for the break payload.
            </div>
          ) : (
            <>
              {/* Phase 2 #2.9: container attribution surfaces above the
                  process tree so the analyst sees container context
                  before drilling into the chain. Hidden when the
                  triggering process is bare-metal. */}
              {data.container ? (
                <div className="mb-3 flex flex-wrap items-center gap-2 rounded-md border bg-muted/40 px-3 py-2 text-xs">
                  <span className="text-muted-foreground">Container</span>
                  {data.container.runtime ? (
                    <span className="rounded-md border bg-background px-1.5 py-0.5 font-mono uppercase tracking-wide">
                      {data.container.runtime}
                    </span>
                  ) : null}
                  <span className="font-mono tabular-nums" title={data.container.id}>
                    {data.container.id.slice(0, 12)}
                  </span>
                  {data.container.image ? (
                    <>
                      <span className="text-muted-foreground">·</span>
                      <span className="truncate font-mono">{data.container.image}</span>
                    </>
                  ) : null}
                </div>
              ) : null}
              {/* Phase 4 #4.1: AI-generated summary + suggested
                  response. Sits above the process tree because the
                  summary is the first thing the analyst should
                  read; "AI analysis pending" until the summariser
                  worker produces a row. */}
              <div className="mb-4">
                <AiSummaryWidget alertId={data.id} />
              </div>
              {/* Phase 2 #2.6: durable process graph from the Postgres
                  `process_chain` table. Renders above the existing
                  OpenSearch-derived chain so analysts see the
                  persisted lineage even when telemetry has rotated
                  out of OpenSearch. */}
              <ProcessGraph alertId={data.id} />
              <div className="mt-4">
                <AlertInvestigation alertId={data.id} />
              </div>
            </>
          )}
        </div>
        <aside className="lg:sticky lg:top-6 lg:self-start">
          <AlertDetailPanel alert={data} />
        </aside>
      </div>
    </>
  );
}
