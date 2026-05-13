/**
 * Phase 1 #1.9: threat-intel feed management.
 *
 * Operators register intel feeds (TAXII / abuse.ch CSV / custom JSON);
 * the ingest worker pulls each enabled feed on its cadence and
 * materialises indicators under a managed Rule of kind=IOC (one rule
 * per feed). This page surfaces feed status (last_pulled_at,
 * entry_count, last_error) and lets admins create / edit / delete /
 * force-pull feeds.
 *
 * Auth tokens are write-only: the API never echoes the plaintext back,
 * so the form keeps a separate "has_auth" indicator and an "Update
 * auth" affordance distinct from the rest of the edit form.
 */
import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Clock, RefreshCw, ShieldAlert, Trash2 } from "lucide-react";

import { intelApi } from "@/api/intel";
import { ApiError } from "@/api/client";
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
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/hooks/useAuth";
import { cn } from "@/lib/utils";
import type { IntelFeed, IntelFeedKind } from "@/types/api";

const KIND_LABEL: Record<IntelFeedKind, string> = {
  taxii: "TAXII 2.1",
  abusech_csv: "abuse.ch CSV",
  custom_json: "Custom JSON",
};

function formatInterval(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

export function Intel() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["intel-feeds"],
    queryFn: () => intelApi.list({ limit: 200 }),
    refetchInterval: 30_000,
  });

  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: intelApi.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["intel-feeds"] });
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const triggerPull = useMutation({
    mutationFn: (id: string) => intelApi.triggerPull(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-feeds"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof intelApi.update>[1] }) =>
      intelApi.update(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-feeds"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => intelApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-feeds"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  return (
    <>
      <PageHeader
        title="Threat-intel feeds"
        description={
          <span>
            Operator-registered indicator sources. The ingest worker pulls each enabled feed on its
            cadence and materialises IOCs under a managed rule per feed. Admins manage; analysts +
            viewers can read.
          </span>
        }
      />
      <div className="grid gap-6 p-8 lg:grid-cols-[1fr_2fr]">
        {isAdmin && (
          <NewFeedCard
            onSubmit={create.mutate}
            error={error}
            pending={create.isPending}
            succeededAt={create.isSuccess ? create.data?.id : undefined}
          />
        )}
        <Card className={isAdmin ? "" : "lg:col-span-2"}>
          <CardHeader>
            <CardTitle>Registered feeds</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>Interval</TableHead>
                  <TableHead>Last pulled</TableHead>
                  <TableHead className="text-right">Entries</TableHead>
                  <TableHead>Status</TableHead>
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
                      No intel feeds registered yet.
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.items.map((f) => (
                  <TableRow key={f.id}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{f.name}</span>
                        <span
                          className="max-w-md truncate font-mono text-[11px] text-muted-foreground"
                          title={f.url}
                        >
                          {f.url}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs uppercase tracking-wider text-muted-foreground">
                        {KIND_LABEL[f.kind]}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums text-muted-foreground">
                      {formatInterval(f.interval_s)}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                      {f.last_pulled_at ? new Date(f.last_pulled_at).toLocaleString() : "—"}
                    </TableCell>
                    <TableCell className="text-right text-xs tabular-nums">
                      {f.entry_count}
                    </TableCell>
                    <TableCell>
                      <FeedStatusBadge feed={f} />
                    </TableCell>
                    {isAdmin && (
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              update.mutate({ id: f.id, body: { enabled: !f.enabled } })
                            }
                            title={f.enabled ? "Disable" : "Enable"}
                          >
                            {f.enabled ? "Disable" : "Enable"}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => triggerPull.mutate(f.id)}
                            disabled={triggerPull.isPending}
                            title="Pull now (ignore cadence)"
                          >
                            <RefreshCw
                              className={cn("h-4 w-4", triggerPull.isPending && "animate-spin")}
                              aria-hidden="true"
                            />
                          </Button>
                          <ConfirmDestructive
                            title="Delete intel feed?"
                            description={
                              <>
                                This removes the feed <span className="font-mono">{f.name}</span>{" "}
                                and its managed rule (along with all materialised IOCs).
                                Operator-created IOCs on other rules are unaffected. This cannot be
                                undone.
                              </>
                            }
                            confirmLabel="Delete feed"
                            onConfirm={() => remove.mutate(f.id)}
                            pending={remove.isPending}
                            trigger={
                              <Button size="sm" variant="ghost">
                                <Trash2 className="h-4 w-4" aria-hidden="true" />
                              </Button>
                            }
                          />
                        </div>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function FeedStatusBadge({ feed }: { feed: IntelFeed }) {
  if (!feed.enabled) {
    return (
      <Badge variant="outline" className="text-xs">
        Disabled
      </Badge>
    );
  }
  if (feed.last_error) {
    return (
      <span
        className="inline-flex items-center gap-1.5 text-xs text-destructive"
        title={feed.last_error}
      >
        <ShieldAlert className="h-3.5 w-3.5" />
        Error
      </span>
    );
  }
  if (feed.last_pulled_at) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-emerald-500">
        <CheckCircle2 className="h-3.5 w-3.5" />
        OK
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
      <Clock className="h-3.5 w-3.5" />
      Pending first pull
    </span>
  );
}

function NewFeedCard({
  onSubmit,
  error,
  pending,
  succeededAt,
}: {
  onSubmit: (body: {
    name: string;
    kind: IntelFeedKind;
    url: string;
    auth?: string;
    interval_s: number;
    enabled: boolean;
  }) => void;
  error: string | null;
  pending: boolean;
  // Newly-created feed id; changes when a create succeeds so the form
  // knows to reset only after the round-trip lands.
  succeededAt: string | undefined;
}) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<IntelFeedKind>("taxii");
  const [url, setUrl] = useState("");
  const [auth, setAuth] = useState("");
  const [intervalH, setIntervalH] = useState(1);
  const [enabled, setEnabled] = useState(true);
  const [lastReset, setLastReset] = useState<string | undefined>(undefined);

  if (succeededAt && succeededAt !== lastReset) {
    setName("");
    setUrl("");
    setAuth("");
    setIntervalH(1);
    setEnabled(true);
    setLastReset(succeededAt);
  }

  const handle = (e: FormEvent) => {
    e.preventDefault();
    onSubmit({
      name: name.trim(),
      kind,
      url: url.trim(),
      auth: auth.trim() || undefined,
      interval_s: Math.max(60, Math.round(intervalH * 3600)),
      enabled,
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Register feed</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handle} className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="intel-name">Name</Label>
            <Input
              id="intel-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="urlhaus"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="intel-kind">Kind</Label>
            <Select value={kind} onValueChange={(v) => setKind(v as IntelFeedKind)}>
              <SelectTrigger id="intel-kind">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="taxii">TAXII 2.1 collection</SelectItem>
                <SelectItem value="abusech_csv">abuse.ch CSV</SelectItem>
                <SelectItem value="custom_json">Custom JSON</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="intel-url">URL</Label>
            <Input
              id="intel-url"
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://…"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="intel-auth">
              Auth <span className="text-xs text-muted-foreground">(optional)</span>
            </Label>
            <Input
              id="intel-auth"
              value={auth}
              onChange={(e) => setAuth(e.target.value)}
              placeholder={
                kind === "taxii"
                  ? "user:password"
                  : kind === "custom_json"
                    ? "Bearer abc123"
                    : "(not used)"
              }
              autoComplete="off"
            />
            <p className="text-[11px] text-muted-foreground">
              Encrypted with the manager's intel key. The plaintext is never read back.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="intel-interval">Pull every (hours)</Label>
            <Input
              id="intel-interval"
              type="number"
              min={0.1}
              max={168}
              step={0.1}
              value={intervalH}
              onChange={(e) => setIntervalH(Number(e.target.value))}
            />
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="intel-enabled"
              checked={enabled}
              onCheckedChange={(v) => setEnabled(Boolean(v))}
            />
            <Label htmlFor="intel-enabled" className="text-sm">
              Enabled
            </Label>
          </div>
          {error && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          <Button type="submit" disabled={pending}>
            Register feed
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
