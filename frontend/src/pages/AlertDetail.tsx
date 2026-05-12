import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { AlertStateBadge, SeverityBadge } from "@/components/badges";
import { AlertDetailPanel } from "@/components/AlertDetailPanel";
import { AlertInvestigation } from "@/components/AlertInvestigation";
import { PageHeader } from "@/components/PageHeader";

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

  return (
    <>
      <PageHeader
        title={data.summary}
        description={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
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
          </span>
        }
        actions={
          <div className="flex items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <AlertStateBadge state={data.state} />
          </div>
        }
      />
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
            <AlertInvestigation alertId={data.id} />
          )}
        </div>
        <aside className="lg:sticky lg:top-6 lg:self-start">
          <AlertDetailPanel alert={data} />
        </aside>
      </div>
    </>
  );
}
