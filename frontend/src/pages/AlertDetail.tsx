import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { AlertStateBadge, SeverityBadge } from "@/components/badges";
import { AlertDetailPanel } from "@/components/AlertDetailPanel";
import { AlertInvestigation } from "@/components/AlertInvestigation";
import { PageHeader } from "@/components/PageHeader";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["alert", id],
    queryFn: () => alertsApi.get(id!),
    enabled: !!id,
  });

  if (isLoading) return <div className="p-8 text-muted-foreground">loading…</div>;
  if (isError) {
    return (
      <div className="p-8 text-destructive">
        {error instanceof ApiError ? error.detail : "failed to load"}
      </div>
    );
  }
  if (!data) return <div className="p-8">not found</div>;

  const hostLabel = data.host_hostname ?? data.host_id.slice(0, 8) + "…";
  const ruleLabel = data.rule_name ?? data.rule_id.slice(0, 8) + "…";

  return (
    <>
      <PageHeader
        title={data.summary}
        description={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span>Alert {data.id.slice(0, 8)}…</span>
            <span>·</span>
            <Link to={`/hosts/${data.host_id}`} className="underline-offset-2 hover:underline">
              {hostLabel}
            </Link>
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
      <div className="mx-auto w-full max-w-7xl px-8 py-6">
        <Tabs defaultValue="investigation" className="w-full">
          <TabsList>
            <TabsTrigger value="investigation">Investigation</TabsTrigger>
            <TabsTrigger value="triage">Triage</TabsTrigger>
          </TabsList>
          <TabsContent value="investigation" className="mt-4">
            <AlertInvestigation alertId={data.id} />
          </TabsContent>
          <TabsContent value="triage" className="mt-4">
            <div className="mx-auto max-w-3xl">
              <AlertDetailPanel alert={data} />
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </>
  );
}
