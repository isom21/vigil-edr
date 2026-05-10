import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight } from "lucide-react";
import { alertsApi } from "@/api/alerts";
import { hostsApi } from "@/api/hosts";
import { AlertStateBadge, SeverityBadge } from "@/components/badges";
import { SEVERITY_HSL } from "@/lib/severity";
import { BarChart, ChartCard, DonutChart, Sparkline } from "@/components/charts";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { cn } from "@/lib/utils";
import type { Severity, StatBucket } from "@/types/api";

const SEVS: { key: Severity; label: string }[] = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
];

function bucket(data: StatBucket[] | undefined, key: string): number {
  return data?.find((b) => b.key === key)?.count ?? 0;
}

export function Dashboard() {
  const sevStats = useQuery({
    queryKey: ["alert-stats", "severity"],
    queryFn: () => alertsApi.stats("severity"),
    refetchInterval: 15_000,
  });
  const stateStats = useQuery({
    queryKey: ["alert-stats", "state"],
    queryFn: () => alertsApi.stats("state"),
    refetchInterval: 15_000,
  });
  const hourStats = useQuery({
    queryKey: ["alert-stats", "hour"],
    queryFn: () => alertsApi.stats("hour"),
    refetchInterval: 60_000,
  });
  const ruleStats = useQuery({
    queryKey: ["alert-stats", "rule"],
    queryFn: () => alertsApi.stats("rule"),
    refetchInterval: 60_000,
  });
  const hostStatusStats = useQuery({
    queryKey: ["host-stats", "status"],
    queryFn: () => hostsApi.stats("status"),
    refetchInterval: 60_000,
  });
  const recent = useQuery({
    queryKey: ["alerts", "dashboard-recent"],
    queryFn: () => alertsApi.list({ limit: 8 }),
    refetchInterval: 10_000,
  });

  const total = sevStats.data?.reduce((s, b) => s + b.count, 0) ?? 0;

  return (
    <>
      <PageHeader title="Dashboard" description="Live overview — counts refresh every 10–60 s." />
      <div className="space-y-6 px-8 py-6">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {SEVS.map(({ key, label }) => {
            const count = bucket(sevStats.data, key);
            return (
              <Link
                key={key}
                to={`/alerts?severity=${key}&state=new`}
                className={cn(
                  "group rounded-lg border p-4 transition-colors hover:border-foreground/40",
                )}
                style={{ borderColor: count > 0 ? SEVERITY_HSL[key] : undefined }}
              >
                <div className="flex items-center justify-between text-xs uppercase tracking-wider text-muted-foreground">
                  <span>{label}</span>
                  <ArrowRight className="h-3 w-3 opacity-0 transition-opacity group-hover:opacity-100" />
                </div>
                <div
                  className="mt-1 text-3xl font-semibold"
                  style={{ color: count > 0 ? SEVERITY_HSL[key] : undefined }}
                >
                  {count}
                </div>
                <div className="mt-1 text-xs text-muted-foreground">open alerts</div>
              </Link>
            );
          })}
        </div>

        <Card>
          <CardContent className="p-4">
            <div className="mb-2 flex items-center justify-between">
              <div>
                <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Last 24 hours
                </div>
                <div className="text-sm">{total} total alerts open</div>
              </div>
              <Link to="/alerts" className="text-xs text-muted-foreground hover:text-foreground">
                Open console <ArrowRight className="inline h-3 w-3" />
              </Link>
            </div>
            <Sparkline
              data={(hourStats.data ?? []).map((b) => ({ ts: b.key, count: b.count }))}
              width={1000}
              height={80}
              color={SEVERITY_HSL.high}
              showAxis
              className="w-full"
            />
          </CardContent>
        </Card>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <ChartCard title="Alert state">
            <DonutChart
              data={[
                {
                  key: "new",
                  label: "new",
                  color: SEVERITY_HSL.medium,
                  count: bucket(stateStats.data, "new"),
                },
                {
                  key: "investigating",
                  label: "investigating",
                  color: SEVERITY_HSL.low,
                  count: bucket(stateStats.data, "investigating"),
                },
                {
                  key: "true_positive",
                  label: "true positive",
                  color: SEVERITY_HSL.critical,
                  count: bucket(stateStats.data, "true_positive"),
                },
                {
                  key: "false_positive",
                  label: "false positive",
                  color: "hsl(var(--muted-foreground))",
                  count: bucket(stateStats.data, "false_positive"),
                },
              ]}
              size={130}
            />
          </ChartCard>
          <ChartCard title="Host status">
            <DonutChart
              data={[
                {
                  key: "online",
                  label: "online",
                  color: "hsl(143 64% 50%)",
                  count: bucket(hostStatusStats.data, "online"),
                },
                {
                  key: "offline",
                  label: "offline",
                  color: "hsl(var(--muted-foreground))",
                  count: bucket(hostStatusStats.data, "offline"),
                },
                {
                  key: "isolated",
                  label: "isolated",
                  color: SEVERITY_HSL.critical,
                  count: bucket(hostStatusStats.data, "isolated"),
                },
                {
                  key: "pending",
                  label: "pending",
                  color: SEVERITY_HSL.medium,
                  count: bucket(hostStatusStats.data, "pending"),
                },
              ]}
              size={130}
            />
          </ChartCard>
          <ChartCard title="Top firing rules">
            <BarChart data={(ruleStats.data ?? []).map((b) => ({ key: b.key, count: b.count }))} />
          </ChartCard>
        </div>

        <Card>
          <CardContent className="p-4">
            <div className="mb-3 flex items-center justify-between">
              <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Recent alerts
              </div>
              <Link to="/alerts" className="text-xs text-muted-foreground hover:text-foreground">
                View all <ArrowRight className="inline h-3 w-3" />
              </Link>
            </div>
            <ul className="divide-y">
              {recent.isLoading && <li className="py-3 text-sm text-muted-foreground">Loading…</li>}
              {recent.data?.items.length === 0 && !recent.isLoading && (
                <li className="py-3 text-sm text-muted-foreground">No alerts yet.</li>
              )}
              {recent.data?.items.map((a) => (
                <li key={a.id} className="flex items-center gap-3 py-2.5 text-sm">
                  <SeverityBadge severity={a.severity} />
                  <Link
                    to={`/alerts?openId=${a.id}`}
                    className="min-w-0 flex-1 truncate hover:underline"
                  >
                    {a.summary}
                  </Link>
                  <span className="hidden text-xs text-muted-foreground sm:inline">
                    {a.host_hostname ?? a.host_id.slice(0, 8)}
                  </span>
                  <AlertStateBadge state={a.state} />
                  <span className="text-xs text-muted-foreground">
                    {new Date(a.opened_at).toLocaleTimeString()}
                  </span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
