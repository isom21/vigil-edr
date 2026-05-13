/**
 * Phase 2 #2.7: vulnerability inventory.
 *
 * Lists (host, CVE) rows materialised by the NVD-driven scanner.
 * Analysts + viewers see the rows their host-group membership lets
 * them see. Admins also get the "Suppress" action which hides a row
 * from the default list without deleting the evidence.
 */
import { FormEvent, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { EyeOff } from "lucide-react";

import { ApiError } from "@/api/client";
import { vulnerabilitiesApi } from "@/api/vulnerabilities";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/hooks/useAuth";
import type { HostVulnerability } from "@/types/api";

const SEVERITY_OPTIONS = ["any", "critical", "high", "medium", "low"] as const;
type SeverityFilter = (typeof SEVERITY_OPTIONS)[number];

function severityBadge(severity: string | null) {
  if (!severity) return <Badge variant="outline">Unscored</Badge>;
  const tone =
    severity === "critical"
      ? "bg-red-600 text-white"
      : severity === "high"
        ? "bg-orange-500 text-white"
        : severity === "medium"
          ? "bg-yellow-500 text-black"
          : "bg-secondary text-secondary-foreground";
  return <Badge className={tone}>{severity}</Badge>;
}

export function Vulnerabilities() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const qc = useQueryClient();

  const [hostFilter, setHostFilter] = useState("");
  const [cveFilter, setCveFilter] = useState("");
  const [severity, setSeverity] = useState<SeverityFilter>("any");
  const [includeSuppressed, setIncludeSuppressed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Submitted filters lag the state so typing in the boxes doesn't
  // refire the query on every keystroke.
  const [submitted, setSubmitted] = useState({ host: "", cve: "" });

  const queryKey = useMemo(
    () => [
      "vulnerabilities",
      { host: submitted.host, cve: submitted.cve, severity, includeSuppressed },
    ],
    [submitted, severity, includeSuppressed],
  );

  const list = useQuery({
    queryKey,
    queryFn: () =>
      vulnerabilitiesApi.list({
        host_id: submitted.host || undefined,
        cve_id: submitted.cve || undefined,
        severity: severity === "any" ? undefined : severity,
        include_suppressed: includeSuppressed,
        limit: 200,
      }),
    refetchInterval: 60_000,
  });

  const suppress = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      vulnerabilitiesApi.suppress(id, reason || undefined),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vulnerabilities"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setSubmitted({ host: hostFilter.trim(), cve: cveFilter.trim() });
  };

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        description={
          <span>
            CVEs the daily NVD-driven scanner found on your fleet. Sorted by CVSS v3 score. Admins
            can suppress noisy rows; the action is audited.
          </span>
        }
      />
      <div className="space-y-4 p-8">
        <Card>
          <CardHeader>
            <CardTitle>Filters</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="grid gap-3 md:grid-cols-5">
              <div className="space-y-1">
                <Label htmlFor="vuln-host">Host id</Label>
                <Input
                  id="vuln-host"
                  value={hostFilter}
                  onChange={(e) => setHostFilter(e.target.value)}
                  placeholder="UUID"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="vuln-cve">CVE</Label>
                <Input
                  id="vuln-cve"
                  value={cveFilter}
                  onChange={(e) => setCveFilter(e.target.value)}
                  placeholder="CVE-2024-…"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="vuln-severity">Severity</Label>
                <Select value={severity} onValueChange={(v) => setSeverity(v as SeverityFilter)}>
                  <SelectTrigger id="vuln-severity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITY_OPTIONS.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-end gap-2">
                <Checkbox
                  id="vuln-suppressed"
                  checked={includeSuppressed}
                  onCheckedChange={(v) => setIncludeSuppressed(Boolean(v))}
                />
                <Label htmlFor="vuln-suppressed" className="text-sm">
                  Include suppressed
                </Label>
              </div>
              <div className="flex items-end">
                <Button type="submit">Apply</Button>
              </div>
            </form>
            {error && (
              <div className="mt-3 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Matched CVEs ({list.data?.total ?? 0})</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead className="text-right">CVSS v3</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>CPE</TableHead>
                  <TableHead>Last seen</TableHead>
                  {isAdmin && <TableHead></TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.isLoading && (
                  <TableRow>
                    <TableCell colSpan={isAdmin ? 7 : 6} className="text-muted-foreground">
                      Loading…
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={isAdmin ? 7 : 6} className="text-muted-foreground">
                      No vulnerabilities match the current filters.
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.items.map((row) => (
                  <VulnRow
                    key={row.id}
                    row={row}
                    isAdmin={isAdmin}
                    onSuppress={(id, reason) => suppress.mutate({ id, reason })}
                    pending={suppress.isPending}
                  />
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function VulnRow({
  row,
  isAdmin,
  onSuppress,
  pending,
}: {
  row: HostVulnerability;
  isAdmin: boolean;
  onSuppress: (id: string, reason: string) => void;
  pending: boolean;
}) {
  const [reason, setReason] = useState("");
  return (
    <TableRow className={row.suppressed ? "opacity-60" : ""}>
      <TableCell>
        <span className="font-mono text-xs">{row.cve_id}</span>
        {row.summary && (
          <div className="max-w-md truncate text-xs text-muted-foreground" title={row.summary}>
            {row.summary}
          </div>
        )}
      </TableCell>
      <TableCell>{severityBadge(row.severity)}</TableCell>
      <TableCell className="text-right text-xs tabular-nums">{row.cvss_v3_score ?? "—"}</TableCell>
      <TableCell>
        <Link to={`/hosts/${row.host_id}`} className="font-mono text-xs hover:underline">
          {row.host_id.slice(0, 8)}…
        </Link>
      </TableCell>
      <TableCell className="max-w-xs truncate font-mono text-[11px] text-muted-foreground">
        {row.cpe ?? "—"}
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
        {new Date(row.last_seen).toLocaleString()}
      </TableCell>
      {isAdmin && (
        <TableCell className="text-right">
          <div className="flex items-center justify-end gap-1">
            <Input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Reason"
              className="h-7 w-32 text-xs"
            />
            <Button
              size="sm"
              variant={row.suppressed ? "outline" : "ghost"}
              onClick={() => onSuppress(row.id, reason)}
              disabled={pending}
              title={row.suppressed ? "Unsuppress" : "Suppress"}
            >
              <EyeOff className="h-4 w-4" aria-hidden="true" />
            </Button>
          </div>
        </TableCell>
      )}
    </TableRow>
  );
}
