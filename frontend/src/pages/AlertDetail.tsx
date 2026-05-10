import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { AlertStateBadge, SeverityBadge } from "@/components/badges";
import { AlertDetailPanel } from "@/components/AlertDetailPanel";
import { PageHeader } from "@/components/PageHeader";

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

  return (
    <>
      <PageHeader
        title={data.summary}
        description={`Alert ${data.id}`}
        actions={
          <div className="flex items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <AlertStateBadge state={data.state} />
          </div>
        }
      />
      <div className="mx-auto max-w-3xl px-8 py-6">
        <AlertDetailPanel alert={data} />
      </div>
    </>
  );
}
