/**
 * Phase 4 #4.2: AWS CloudTrail IAM-anomaly source registration.
 *
 * Operators register S3 buckets that hold CloudTrail logs; the
 * cloud-iam-monitor worker pulls new objects on its cadence and
 * fires synthetic alerts when fresh events escape the per-(source,
 * principal) baseline. Admin-only writes; analysts + viewers can
 * read the list to see which AWS accounts are wired up.
 *
 * The AWS secret access key is write-only — the API never echoes the
 * plaintext back; ``has_credentials`` is the indicator that a working
 * pair is on file. The access key id is shown so operators can
 * eyeball which AWS principal the integration is using.
 */
import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Clock, ShieldAlert, Trash2 } from "lucide-react";

import { cloudApi } from "@/api/cloud";
import { ApiError } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import type { CloudSource } from "@/types/api";

export function CloudSources() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["cloud-sources"],
    queryFn: cloudApi.list,
    refetchInterval: 30_000,
  });

  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: cloudApi.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cloud-sources"] });
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof cloudApi.update>[1] }) =>
      cloudApi.update(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cloud-sources"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => cloudApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cloud-sources"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  return (
    <>
      <PageHeader
        title="Cloud sources"
        description={
          <span>
            Operator-registered AWS CloudTrail S3 buckets. The cloud-IAM-anomaly monitor pulls each
            enabled source on its cadence and fires alerts on never-before-seen principals, actions,
            or regions. Admins manage; analysts and viewers can read.
          </span>
        }
      />
      <div className="grid gap-6 p-8 lg:grid-cols-[1fr_2fr]">
        {isAdmin && (
          <NewSourceCard
            onSubmit={create.mutate}
            error={error}
            pending={create.isPending}
            succeededAt={create.isSuccess ? create.data?.id : undefined}
          />
        )}
        <Card className={isAdmin ? "" : "lg:col-span-2"}>
          <CardHeader>
            <CardTitle>Registered sources</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Bucket / prefix</TableHead>
                  <TableHead>Region</TableHead>
                  <TableHead>Access key</TableHead>
                  <TableHead>Last polled</TableHead>
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
                {list.data?.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={isAdmin ? 7 : 6} className="text-muted-foreground">
                      No cloud sources registered yet.
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <span className="font-medium">{s.name}</span>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-mono text-[11px]">{s.bucket}</span>
                        {s.prefix && (
                          <span className="font-mono text-[11px] text-muted-foreground">
                            {s.prefix}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{s.region}</TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {s.aws_access_key_id || "—"}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                      {s.last_polled_at ? new Date(s.last_polled_at).toLocaleString() : "—"}
                    </TableCell>
                    <TableCell>
                      <SourceStatusBadge source={s} />
                    </TableCell>
                    {isAdmin && (
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              update.mutate({ id: s.id, body: { enabled: !s.enabled } })
                            }
                            title={s.enabled ? "Disable" : "Enable"}
                          >
                            {s.enabled ? "Disable" : "Enable"}
                          </Button>
                          <ConfirmDestructive
                            title="Delete cloud source?"
                            description={
                              <>
                                This removes the source <span className="font-mono">{s.name}</span>{" "}
                                and every baseline row for it. Past alerts stay; future events from
                                this bucket stop flowing.
                              </>
                            }
                            confirmLabel="Delete source"
                            onConfirm={() => remove.mutate(s.id)}
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

function SourceStatusBadge({ source }: { source: CloudSource }) {
  if (!source.enabled) {
    return (
      <Badge variant="outline" className="text-xs">
        Disabled
      </Badge>
    );
  }
  if (!source.has_credentials) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-destructive">
        <ShieldAlert className="h-3.5 w-3.5" />
        No credentials
      </span>
    );
  }
  if (source.last_polled_at) {
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
      Pending first poll
    </span>
  );
}

function NewSourceCard({
  onSubmit,
  error,
  pending,
  succeededAt,
}: {
  onSubmit: (body: {
    name: string;
    kind: "aws_cloudtrail";
    bucket: string;
    prefix: string;
    region: string;
    aws_access_key_id: string;
    aws_secret_access_key: string;
    enabled: boolean;
  }) => void;
  error: string | null;
  pending: boolean;
  succeededAt: string | undefined;
}) {
  const [name, setName] = useState("");
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("AWSLogs/");
  const [region, setRegion] = useState("us-east-1");
  const [accessKey, setAccessKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [lastReset, setLastReset] = useState<string | undefined>(undefined);

  if (succeededAt && succeededAt !== lastReset) {
    setName("");
    setBucket("");
    setPrefix("AWSLogs/");
    setRegion("us-east-1");
    setAccessKey("");
    setSecretKey("");
    setEnabled(true);
    setLastReset(succeededAt);
  }

  const handle = (e: FormEvent) => {
    e.preventDefault();
    onSubmit({
      name: name.trim(),
      kind: "aws_cloudtrail",
      bucket: bucket.trim(),
      prefix: prefix.trim(),
      region: region.trim(),
      aws_access_key_id: accessKey.trim(),
      aws_secret_access_key: secretKey,
      enabled,
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Register source</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handle} className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="cloud-name">Name</Label>
            <Input
              id="cloud-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="prod-cloudtrail"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cloud-bucket">S3 bucket</Label>
            <Input
              id="cloud-bucket"
              value={bucket}
              onChange={(e) => setBucket(e.target.value)}
              placeholder="acme-cloudtrail-prod"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cloud-prefix">
              Prefix <span className="text-xs text-muted-foreground">(optional)</span>
            </Label>
            <Input
              id="cloud-prefix"
              value={prefix}
              onChange={(e) => setPrefix(e.target.value)}
              placeholder="AWSLogs/123456789012/CloudTrail/"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cloud-region">AWS region</Label>
            <Input
              id="cloud-region"
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              placeholder="us-east-1"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cloud-access-key">AWS access key ID</Label>
            <Input
              id="cloud-access-key"
              value={accessKey}
              onChange={(e) => setAccessKey(e.target.value)}
              placeholder="AKIA…"
              autoComplete="off"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cloud-secret-key">AWS secret access key</Label>
            <Input
              id="cloud-secret-key"
              type="password"
              value={secretKey}
              onChange={(e) => setSecretKey(e.target.value)}
              autoComplete="off"
              required
            />
            <p className="text-[11px] text-muted-foreground">
              Encrypted with the manager's config key. The plaintext is never read back.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="cloud-enabled"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <Label htmlFor="cloud-enabled" className="text-sm">
              Enabled
            </Label>
          </div>
          {error && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          <Button type="submit" disabled={pending}>
            Register source
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
