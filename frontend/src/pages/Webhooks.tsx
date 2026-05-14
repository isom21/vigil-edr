/**
 * Webhook subscriptions (Phase 3 #3.7).
 *
 * Admin-only writes; operators register URLs that receive HMAC-signed
 * JSON notifications on enumerated event types. The create dialog
 * minted a fresh signing secret and shows it once — there's no
 * subsequent path to retrieve it; rotation issues a new value.
 *
 * The list view mirrors the SIEM destinations page (table on the
 * left, dialog-driven create / edit), with extra columns for the
 * delivery health summary (enabled state, last delivery timestamp,
 * rolling failure count).
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertOctagon, Check, Copy, KeyRound, ListTree, Plus, Send, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { webhooksApi } from "@/api/webhooks";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/useAuth";
import type {
  WebhookEventType,
  WebhookSubscription,
  WebhookSubscriptionCreateResponse,
} from "@/types/api";
import { WEBHOOK_EVENT_TYPES } from "@/types/api";

const EVENT_TYPE_LABELS: Record<WebhookEventType, string> = {
  "alert.opened": "Alert opened",
  "alert.state_changed": "Alert state changed",
  "alert.summary_ready": "Alert summary ready",
  "incident.opened": "Incident opened",
  "incident.resolved": "Incident resolved",
  "job.completed": "Job completed",
  "job.failed": "Job failed",
  "host.enrolled": "Host enrolled",
  "host.disconnected": "Host disconnected",
};

function formatTimestamp(ts: string | null): string {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export function Webhooks() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const list = useQuery({
    queryKey: ["webhooks"],
    queryFn: webhooksApi.list,
    refetchInterval: 15_000,
  });

  const [createOpen, setCreateOpen] = useState(false);
  const [revealed, setRevealed] = useState<WebhookSubscriptionCreateResponse | null>(null);

  const toggleEnabled = useMutation({
    mutationFn: (s: WebhookSubscription) => webhooksApi.update(s.id, { enabled: !s.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => webhooksApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });

  const test = useMutation({
    mutationFn: async (s: WebhookSubscription) => {
      // Fire the first event type the subscription actually accepts.
      const eventType = s.event_types[0] ?? "alert.opened";
      return webhooksApi.test(s.id, eventType as WebhookEventType);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });

  const rotate = useMutation({
    mutationFn: (id: string) => webhooksApi.rotate(id),
    onSuccess: (data) => {
      setRevealed(data);
      qc.invalidateQueries({ queryKey: ["webhooks"] });
    },
  });

  if (!isAdmin) {
    return (
      <>
        <PageHeader title="Webhooks" />
        <div className="p-8 text-sm text-muted-foreground">
          Webhook subscriptions are admin-only.
        </div>
      </>
    );
  }

  const items = list.data ?? [];

  return (
    <>
      <PageHeader
        title="Webhooks"
        description={`${items.length} subscription${items.length === 1 ? "" : "s"} · HMAC-signed JSON delivery on registered event types.`}
        actions={
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            New webhook
          </Button>
        }
      />
      <div className="space-y-4 px-8 py-6">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Subscriptions</CardTitle>
          </CardHeader>
          <CardContent>
            {list.isLoading && (
              <p className="text-sm text-muted-foreground">Loading subscriptions…</p>
            )}
            {!list.isLoading && items.length === 0 && (
              <p className="text-sm text-muted-foreground">
                No webhook subscriptions yet. Click <span className="font-mono">New webhook</span>{" "}
                to add one.
              </p>
            )}
            <ul className="divide-y divide-border">
              {items.map((s) => (
                <li key={s.id} className="flex items-start justify-between gap-3 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{s.name}</span>
                      {s.enabled ? (
                        <span className="text-[10px] uppercase tracking-wider text-emerald-500">
                          enabled
                        </span>
                      ) : (
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                          disabled
                        </span>
                      )}
                      {s.failure_count > 0 && (
                        <span className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-amber-500">
                          <AlertOctagon className="h-3 w-3" aria-hidden="true" />
                          {s.failure_count} fail
                          {s.failure_count === 1 ? "" : "s"}
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
                      {s.url}
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {s.event_types.map((evt) => (
                        <span
                          key={evt}
                          className="rounded-sm bg-secondary px-1.5 py-0.5 text-[10px] tracking-wider text-muted-foreground"
                        >
                          {evt}
                        </span>
                      ))}
                    </div>
                    <div className="mt-1 text-[11px] text-muted-foreground">
                      Last delivery: {formatTimestamp(s.last_delivery_at)} · Last failure:{" "}
                      {formatTimestamp(s.last_failure_at)}
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-1">
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => test.mutate(s)}
                      disabled={!s.enabled || test.isPending}
                      title="Send a synthetic delivery"
                    >
                      <Send className="h-3.5 w-3.5" aria-hidden="true" />
                      Test
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => rotate.mutate(s.id)}
                      title="Rotate signing secret"
                    >
                      <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
                      Rotate
                    </Button>
                    <Button asChild size="sm" variant="secondary" title="View delivery history">
                      <Link to={`/webhooks/${s.id}/deliveries`}>
                        <ListTree className="h-3.5 w-3.5" aria-hidden="true" />
                        Deliveries
                      </Link>
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => toggleEnabled.mutate(s)}>
                      {s.enabled ? "Disable" : "Enable"}
                    </Button>
                    <ConfirmDestructive
                      trigger={
                        <Button size="sm" variant="destructive" title="Delete subscription">
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        </Button>
                      }
                      title={`Delete "${s.name}"?`}
                      description={
                        <>
                          Permanently removes the subscription and every recorded delivery row. This
                          cannot be undone.
                        </>
                      }
                      confirmLabel="Yes, delete"
                      onConfirm={() => remove.mutate(s.id)}
                      pending={remove.isPending}
                    />
                  </div>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
        {test.isError && (
          <p className="text-sm text-destructive">
            Test delivery failed:{" "}
            {test.error instanceof ApiError ? test.error.detail : "request error"}
          </p>
        )}
        {test.isSuccess && test.data && (
          <p className="text-sm text-muted-foreground">
            Last test: {test.data.status} (HTTP {test.data.response_status ?? "—"})
          </p>
        )}
      </div>

      <CreateDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(data) => {
          setRevealed(data);
          setCreateOpen(false);
          qc.invalidateQueries({ queryKey: ["webhooks"] });
        }}
      />

      <RevealSecretDialog data={revealed} onClose={() => setRevealed(null)} />
    </>
  );
}

interface CreateDialogProps {
  open: boolean;
  onClose: () => void;
  onCreated: (data: WebhookSubscriptionCreateResponse) => void;
}

function CreateDialog({ open, onClose, onCreated }: CreateDialogProps) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [eventTypes, setEventTypes] = useState<Set<WebhookEventType>>(new Set());
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setName("");
    setUrl("");
    setEventTypes(new Set());
    setError(null);
  };

  const create = useMutation({
    mutationFn: () =>
      webhooksApi.create({
        name: name.trim(),
        url: url.trim(),
        event_types: Array.from(eventTypes),
      }),
    onSuccess: (data) => {
      reset();
      onCreated(data);
    },
    onError: (e) => {
      setError(e instanceof ApiError ? e.detail : "create failed");
    },
  });

  const valid = name.trim().length > 0 && url.trim().length > 0 && eventTypes.size > 0;

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          reset();
          onClose();
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New webhook subscription</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div>
            <Label htmlFor="wh-name">Name</Label>
            <Input
              id="wh-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="ops-pager"
              autoFocus
            />
          </div>
          <div>
            <Label htmlFor="wh-url">Receiver URL</Label>
            <Input
              id="wh-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://hooks.example/vigil"
            />
            <p className="mt-1 text-[11px] text-muted-foreground">
              Receivers MUST verify the <span className="font-mono">X-Vigil-Signature</span> header
              — HMAC-SHA256 of the JSON body, keyed off the secret returned once on create.
            </p>
          </div>
          <fieldset>
            <legend className="text-sm font-medium">Event types</legend>
            <div className="mt-1 grid grid-cols-2 gap-2">
              {WEBHOOK_EVENT_TYPES.map((evt) => {
                const checked = eventTypes.has(evt);
                return (
                  <label key={evt} className="flex cursor-pointer items-center gap-2 text-sm">
                    <Checkbox
                      checked={checked}
                      onChange={(e) => {
                        const next = new Set(eventTypes);
                        if (e.currentTarget.checked) next.add(evt);
                        else next.delete(evt);
                        setEventTypes(next);
                      }}
                    />
                    <span>
                      <span className="font-medium">{EVENT_TYPE_LABELS[evt]}</span>
                      <span className="ml-1 font-mono text-[11px] text-muted-foreground">
                        {evt}
                      </span>
                    </span>
                  </label>
                );
              })}
            </div>
          </fieldset>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="secondary" onClick={() => onClose()}>
            Cancel
          </Button>
          <Button disabled={!valid || create.isPending} onClick={() => create.mutate()}>
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface RevealSecretDialogProps {
  data: WebhookSubscriptionCreateResponse | null;
  onClose: () => void;
}

function RevealSecretDialog({ data, onClose }: RevealSecretDialogProps) {
  const [copied, setCopied] = useState(false);
  if (!data) return null;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(data.secret);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard might be unavailable (insecure context, denied
      // permission). The user can still copy manually — the secret is
      // visible in the read-only field.
    }
  };

  return (
    <Dialog open={data !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Signing secret — copy now</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <p className="text-sm">
            This is the only time the signing secret for{" "}
            <span className="font-mono">{data.name}</span> will be shown. Configure your receiver to
            verify the <span className="font-mono">X-Vigil-Signature</span> header with it before
            the next event fires.
          </p>
          <div className="flex items-center gap-2">
            <Input
              readOnly
              value={data.secret}
              className="font-mono text-xs"
              onFocus={(e) => e.currentTarget.select()}
            />
            <Button size="sm" variant="secondary" onClick={copy}>
              {copied ? (
                <Check className="h-3.5 w-3.5" aria-hidden="true" />
              ) : (
                <Copy className="h-3.5 w-3.5" aria-hidden="true" />
              )}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={onClose}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
