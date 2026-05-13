import { Link, useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { TerminalSquare } from "lucide-react";
import { alertsApi } from "@/api/alerts";
import { hostsApi } from "@/api/hosts";
import { useAuth } from "@/hooks/useAuth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { HostLiveTelemetry } from "@/components/HostLiveTelemetry";
import { HostQuarantinePanel } from "@/components/HostQuarantinePanel";
import { PageHeader } from "@/components/PageHeader";

export function HostDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  const host = useQuery({
    queryKey: ["host", id],
    queryFn: () => hostsApi.get(id!),
    enabled: !!id,
  });
  const alerts = useQuery({
    queryKey: ["alerts", { host_id: id }],
    queryFn: () => alertsApi.list({ host_id: id, limit: 50 }),
    enabled: !!id,
  });

  if (host.isLoading) {
    return <div className="p-8 text-muted-foreground">Loading…</div>;
  }
  if (!host.data) return <div className="p-8">Not found.</div>;
  const h = host.data;

  // Phase 1 #1.4: Open terminal is an analyst+ response action. The
  // backend re-enforces the role on the POST, but hiding the button
  // for viewers keeps the UI honest.
  const canOpenTerminal = user?.role === "analyst" || user?.role === "admin";

  return (
    <>
      <PageHeader
        title={h.hostname}
        description={`${h.os_platform ?? h.os_family} · ${h.id}`}
        actions={
          canOpenTerminal ? (
            <Button
              variant="outline"
              onClick={() => navigate(`/hosts/${h.id}/terminal`)}
              aria-label="Open remote terminal"
            >
              <TerminalSquare className="mr-2 h-4 w-4" />
              Open terminal
            </Button>
          ) : undefined
        }
      />
      <div className="mx-auto w-full max-w-[1600px] px-6 py-6">
        <Tabs defaultValue="overview" className="w-full">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="telemetry">Live telemetry</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="mt-4">
            <div className="grid gap-4 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Details</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <Row label="OS family" value={h.os_family} />
                  <Row label="OS version" value={h.os_version ?? "—"} />
                  <Row label="Architecture" value={h.os_arch ?? "—"} />
                  <Row label="Agent version" value={h.agent_version ?? "—"} />
                  <Row label="Status" value={<Badge>{h.status}</Badge>} />
                  <Row
                    label="Enrolled"
                    value={h.enrolled_at ? new Date(h.enrolled_at).toLocaleString() : "never"}
                  />
                  <Row
                    label="Last seen"
                    value={h.last_seen_at ? new Date(h.last_seen_at).toLocaleString() : "never"}
                  />
                  <Row label="Policy" value={h.policy_id ?? "—"} />
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Recent alerts ({alerts.data?.total ?? 0})</CardTitle>
                </CardHeader>
                <CardContent>
                  {alerts.data?.items.length ? (
                    <ul className="space-y-2 text-sm">
                      {alerts.data.items.map((a) => (
                        <li
                          key={a.id}
                          className="flex items-center justify-between rounded-md border p-2"
                        >
                          <Link to={`/alerts/${a.id}`} className="min-w-0 flex-1 hover:underline">
                            <div className="truncate font-medium">{a.summary}</div>
                            <div className="text-xs text-muted-foreground">
                              <time dateTime={a.opened_at}>
                                {new Date(a.opened_at).toLocaleString()}
                              </time>{" "}
                              · {a.severity}
                            </div>
                          </Link>
                          <Badge variant="outline">{a.state}</Badge>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-muted-foreground">No alerts yet.</p>
                  )}
                </CardContent>
              </Card>
              <div className="lg:col-span-2">
                <HostQuarantinePanel hostId={h.id} />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="telemetry" className="mt-4">
            <HostLiveTelemetry hostId={h.id} />
          </TabsContent>
        </Tabs>
      </div>
    </>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
