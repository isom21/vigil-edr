import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { TerminalSquare } from "lucide-react";
import type { AttestationBlock, AttestationStatus, PcrValue } from "@/types/api";
import { alertsApi } from "@/api/alerts";
import { hostsApi } from "@/api/hosts";
import { vulnerabilitiesApi } from "@/api/vulnerabilities";
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
  // Phase 2 #2.7: vulnerability assessment.
  const vulns = useQuery({
    queryKey: ["host-vulnerabilities", id],
    queryFn: () => vulnerabilitiesApi.listForHost(id!, { limit: 200 }),
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
            <TabsTrigger value="vulnerabilities">
              Vulnerabilities ({vulns.data?.total ?? 0})
            </TabsTrigger>
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
                  {/* Phase 2 #2.9: container runtimes seen on this host
                      in the last 24h. Empty list → render an em-dash so
                      the layout doesn't shift when telemetry arrives. */}
                  <Row
                    label="Container runtimes (24h)"
                    value={
                      h.container_runtimes_seen.length > 0 ? (
                        <span className="flex flex-wrap items-center justify-end gap-1">
                          {h.container_runtimes_seen.map((rt) => (
                            <Badge key={rt} variant="outline">
                              {rt}
                            </Badge>
                          ))}
                        </span>
                      ) : (
                        "—"
                      )
                    }
                  />
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
              <div className="lg:col-span-2">
                <AttestationPanel hostId={h.id} attestation={h.attestation} />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="telemetry" className="mt-4">
            <HostLiveTelemetry hostId={h.id} />
          </TabsContent>

          <TabsContent value="vulnerabilities" className="mt-4">
            <Card>
              <CardHeader>
                <CardTitle>Detected CVEs ({vulns.data?.total ?? 0})</CardTitle>
              </CardHeader>
              <CardContent>
                {vulns.isLoading ? (
                  <p className="text-sm text-muted-foreground">Loading…</p>
                ) : vulns.data?.items.length ? (
                  <ul className="space-y-2 text-sm">
                    {vulns.data.items.map((v) => (
                      <li
                        key={v.id}
                        className="flex items-center justify-between gap-3 rounded-md border p-2"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="font-mono text-xs">{v.cve_id}</div>
                          {v.summary && (
                            <div
                              className="truncate text-xs text-muted-foreground"
                              title={v.summary}
                            >
                              {v.summary}
                            </div>
                          )}
                        </div>
                        <Badge variant="outline" className="uppercase">
                          {v.severity ?? "—"}
                        </Badge>
                        <span className="text-xs tabular-nums text-muted-foreground">
                          CVSS {v.cvss_v3_score ?? "—"}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    No CVEs detected. The daily scanner is the source of record.
                  </p>
                )}
              </CardContent>
            </Card>
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

// Phase 4 #4.10 — TPM-backed boot-state attestation pane.
const STATUS_LABEL: Record<AttestationStatus, string> = {
  ok: "OK",
  diverged: "Diverged",
  unverified: "Unverified",
  unknown: "Unknown",
};

const STATUS_VARIANT: Record<
  AttestationStatus,
  "default" | "destructive" | "outline" | "secondary"
> = {
  ok: "default",
  diverged: "destructive",
  unverified: "secondary",
  unknown: "outline",
};

function AttestationPanel({
  hostId,
  attestation,
}: {
  hostId: string;
  attestation: AttestationBlock | null;
}) {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const isAdmin = user?.role === "admin";

  // Build the diff set once so the table can highlight in O(1) per row.
  const block = attestation ?? {
    status: "unknown" as AttestationStatus,
    latest: null,
    golden: null,
  };
  const divergedSet = new Set(block.latest?.diverged_pcrs ?? []);

  const requestMutation = useMutation({
    mutationFn: () => hostsApi.requestAttestation(hostId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["host", hostId] }),
  });
  const promoteMutation = useMutation({
    mutationFn: () => hostsApi.promoteAttestation(hostId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["host", hostId] }),
  });

  // Render order anchors on the golden so diff rows track the baseline.
  // Fall back to the latest event when no golden has been promoted yet.
  const rows = (block.golden?.pcr_values_json ?? block.latest?.pcr_values_json ?? []).slice();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3">
          <span>Boot attestation (TPM)</span>
          <Badge variant={STATUS_VARIANT[block.status]}>{STATUS_LABEL[block.status]}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {block.status === "unknown" ? (
          <p className="text-muted-foreground">
            No PCR reports received yet. Hosts without a TPM (containers, older hardware) don't
            surface boot-state attestation.
          </p>
        ) : (
          <>
            <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
              <span>
                Golden: {block.golden ? new Date(block.golden.recorded_at).toLocaleString() : "—"}
              </span>
              <span>
                Latest: {block.latest ? new Date(block.latest.recorded_at).toLocaleString() : "—"}
              </span>
            </div>
            <PcrTable
              rows={rows as PcrValue[]}
              latest={block.latest?.pcr_values_json as PcrValue[] | undefined}
              divergedSet={divergedSet}
            />
          </>
        )}
        {isAdmin && (
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => requestMutation.mutate()}
              disabled={requestMutation.isPending}
            >
              Request fresh quote
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => promoteMutation.mutate()}
              disabled={promoteMutation.isPending || block.latest === null}
              title={
                block.latest === null
                  ? "No event to promote yet"
                  : "Record the latest event as the golden baseline"
              }
            >
              Promote latest → golden
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function PcrTable({
  rows,
  latest,
  divergedSet,
}: {
  rows: PcrValue[];
  latest?: PcrValue[];
  divergedSet: Set<number>;
}) {
  if (rows.length === 0) {
    return (
      <p className="text-muted-foreground">
        No PCR data — promote the next quote to record a baseline.
      </p>
    );
  }
  const latestMap = new Map((latest ?? []).map((p) => [`${p.bank}:${p.index}`, p.digest_hex]));
  return (
    <div className="rounded-md border">
      <table className="w-full text-xs">
        <thead className="bg-muted/50 text-left">
          <tr>
            <th className="px-2 py-1">PCR</th>
            <th className="px-2 py-1">Bank</th>
            <th className="px-2 py-1">Golden digest</th>
            <th className="px-2 py-1">Latest digest</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const drifted = divergedSet.has(row.index);
            const latestDigest = latestMap.get(`${row.bank}:${row.index}`);
            return (
              <tr
                key={`${row.bank}:${row.index}`}
                className={drifted ? "bg-destructive/10" : undefined}
              >
                <td className="px-2 py-1 font-mono">{row.index}</td>
                <td className="px-2 py-1">{row.bank}</td>
                <td className="px-2 py-1 font-mono">{shorten(row.digest_hex)}</td>
                <td className="px-2 py-1 font-mono">{shorten(latestDigest)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function shorten(hex: string | undefined): string {
  if (!hex) return "—";
  if (hex.length <= 20) return hex;
  return `${hex.slice(0, 10)}…${hex.slice(-6)}`;
}
