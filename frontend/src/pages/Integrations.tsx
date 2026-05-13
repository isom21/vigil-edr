/**
 * Alert routing — channels + routing rules CRUD (Phase 1 #1.7).
 *
 * Admins manage credentialed channels (Slack incoming webhook,
 * PagerDuty Events v2 integration key, SMTP destination) and the
 * declarative rules that fire them ("alerts matching <severity / kind
 * / host group> → channels"). Analysts get read-only visibility — they
 * see WHICH channels exist (without secrets) but can't mutate them.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { ApiError } from "@/api/client";
import { hostGroupsApi } from "@/api/hostGroups";
import { notificationsApi } from "@/api/notifications";
import { routingApi } from "@/api/routing";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/useAuth";
import type {
  NotificationChannel,
  NotificationChannelKind,
  RoutingRule,
  RuleKind,
  Severity,
} from "@/types/api";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
const RULE_KINDS: RuleKind[] = ["sigma", "yara", "ioc"];
const CHANNEL_KINDS: NotificationChannelKind[] = ["slack", "pagerduty", "email"];

export function Integrations() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const channelsQ = useQuery({
    queryKey: ["notification-channels"],
    queryFn: () => notificationsApi.list(),
  });
  const rulesQ = useQuery({
    queryKey: ["routing-rules"],
    queryFn: () => routingApi.list(),
  });
  const hostGroupsQ = useQuery({
    queryKey: ["host-groups", { limit: 200 }],
    queryFn: () => hostGroupsApi.list({ limit: 200 }),
  });

  const [newChannelOpen, setNewChannelOpen] = useState(false);
  const [newRuleOpen, setNewRuleOpen] = useState(false);

  return (
    <>
      <PageHeader
        title="Alert routing"
        description={
          isAdmin
            ? "Wire alerts to Slack, PagerDuty, or SMTP destinations. Credentials are Fernet-encrypted at rest and never returned to the UI."
            : "Read-only view. Ask an admin to add or rotate channels and rules."
        }
        actions={
          isAdmin ? (
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => setNewChannelOpen(true)}>
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                New channel
              </Button>
              <Button size="sm" onClick={() => setNewRuleOpen(true)}>
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                New rule
              </Button>
            </div>
          ) : null
        }
      />
      <div className="grid gap-6 px-8 py-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Notification channels</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {channelsQ.isLoading ? (
              <p className="text-xs text-muted-foreground">Loading…</p>
            ) : (channelsQ.data?.length ?? 0) === 0 ? (
              <p className="text-xs text-muted-foreground">
                No channels yet. Create a Slack / PagerDuty / SMTP destination to start routing.
              </p>
            ) : (
              <ul className="space-y-1">
                {channelsQ.data?.map((ch) => (
                  <li key={ch.id}>
                    <ChannelRow channel={ch} isAdmin={isAdmin} />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Routing rules</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {rulesQ.isLoading ? (
              <p className="text-xs text-muted-foreground">Loading…</p>
            ) : (rulesQ.data?.length ?? 0) === 0 ? (
              <p className="text-xs text-muted-foreground">
                No rules yet. A channel won&apos;t fire until at least one rule selects it.
              </p>
            ) : (
              <ul className="space-y-1">
                {rulesQ.data?.map((r) => (
                  <li key={r.id}>
                    <RuleRow
                      rule={r}
                      channels={channelsQ.data ?? []}
                      hostGroups={hostGroupsQ.data?.items ?? []}
                      isAdmin={isAdmin}
                    />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      {newChannelOpen && <ChannelDialog mode="create" onClose={() => setNewChannelOpen(false)} />}
      {newRuleOpen && (
        <RuleDialog
          mode="create"
          channels={channelsQ.data ?? []}
          hostGroups={hostGroupsQ.data?.items ?? []}
          onClose={() => setNewRuleOpen(false)}
        />
      )}
    </>
  );
}

// ---------- Channel row + dialog ----------

function ChannelRow({ channel, isAdmin }: { channel: NotificationChannel; isAdmin: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() => isAdmin && setOpen(true)}
        className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm transition ${
          isAdmin ? "hover:bg-secondary/50" : "cursor-default"
        }`}
      >
        <div className="flex flex-col">
          <span className="font-medium">{channel.name}</span>
          <span className="text-xs text-muted-foreground">
            {channel.kind}
            {channel.secret_fingerprint ? ` · fp ${channel.secret_fingerprint}` : ""}
          </span>
        </div>
        <span
          className={`text-[10px] font-medium uppercase tracking-wider ${
            channel.enabled ? "text-emerald-500" : "text-muted-foreground"
          }`}
        >
          {channel.enabled ? "enabled" : "disabled"}
        </span>
      </button>
      {open && <ChannelDialog mode="edit" channel={channel} onClose={() => setOpen(false)} />}
    </>
  );
}

interface ChannelFormState {
  name: string;
  kind: NotificationChannelKind;
  enabled: boolean;
  // Free-form key/value editor backed by JSON. Keeps the same UI for
  // all three kinds; we hint the operator with placeholders.
  configJson: string;
}

function emptyChannelForm(): ChannelFormState {
  return {
    name: "",
    kind: "slack",
    enabled: true,
    configJson: '{"webhook_url": "https://hooks.slack.com/services/..."}',
  };
}

function placeholderFor(kind: NotificationChannelKind): string {
  if (kind === "slack") return '{"webhook_url": "https://hooks.slack.com/services/..."}';
  if (kind === "pagerduty") return '{"integration_key": "..."}';
  return JSON.stringify(
    {
      smtp_host: "mail.example",
      smtp_port: 587,
      use_starttls: true,
      smtp_user: "alerts@example",
      smtp_password: "...",
      from_addr: "alerts@example",
      to_addr: "soc@example",
    },
    null,
    2,
  );
}

function ChannelDialog({
  mode,
  channel,
  onClose,
}: {
  mode: "create" | "edit";
  channel?: NotificationChannel;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [form, setForm] = useState<ChannelFormState>(() =>
    channel
      ? {
          name: channel.name,
          kind: channel.kind,
          enabled: channel.enabled,
          configJson: "",
        }
      : emptyChannelForm(),
  );
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => {
      const parsed = parseJsonOrThrow(form.configJson);
      return notificationsApi.create({
        name: form.name,
        kind: form.kind,
        config: parsed,
        enabled: form.enabled,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels"] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail : String(e)),
  });

  const update = useMutation({
    mutationFn: () => {
      if (!channel) throw new Error("no channel");
      const body: {
        name?: string;
        config?: Record<string, unknown>;
        enabled?: boolean;
      } = {};
      if (form.name !== channel.name) body.name = form.name;
      if (form.enabled !== channel.enabled) body.enabled = form.enabled;
      if (form.configJson.trim()) body.config = parseJsonOrThrow(form.configJson);
      return notificationsApi.update(channel.id, body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels"] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail : String(e)),
  });

  const remove = useMutation({
    mutationFn: () => {
      if (!channel) throw new Error("no channel");
      return notificationsApi.remove(channel.id);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels"] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail : String(e)),
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {mode === "create" ? "New notification channel" : `Edit ${channel?.name}`}
          </DialogTitle>
        </DialogHeader>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            if (mode === "create") create.mutate();
            else update.mutate();
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="ch-name">Name</Label>
            <Input
              id="ch-name"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              required
              maxLength={128}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="ch-kind">Kind</Label>
              <Select
                id="ch-kind"
                value={form.kind}
                disabled={mode === "edit"}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    kind: e.target.value as NotificationChannelKind,
                    configJson: placeholderFor(e.target.value as NotificationChannelKind),
                  }))
                }
              >
                {CHANNEL_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="ch-enabled">Status</Label>
              <Select
                id="ch-enabled"
                value={form.enabled ? "enabled" : "disabled"}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.value === "enabled" }))}
              >
                <option value="enabled">enabled</option>
                <option value="disabled">disabled</option>
              </Select>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="ch-config">
              Credentials (JSON
              {mode === "edit" ? "; leave blank to keep existing" : ""})
            </Label>
            <Textarea
              id="ch-config"
              rows={8}
              value={form.configJson}
              onChange={(e) => setForm((f) => ({ ...f, configJson: e.target.value }))}
              placeholder={placeholderFor(form.kind)}
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">
              Stored Fernet-encrypted. Audit log records a sha256 fingerprint, never the plaintext.
            </p>
          </div>
          {error && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          <DialogFooter className="flex items-center justify-between">
            {mode === "edit" && channel && (
              <ConfirmDestructive
                title="Delete channel?"
                description={
                  <>
                    <span className="font-mono">{channel.name}</span> will be removed. Routing rules
                    that reference it will silently skip it on next fire.
                  </>
                }
                confirmLabel="Yes, delete"
                onConfirm={() => remove.mutate()}
                pending={remove.isPending}
                trigger={
                  <Button type="button" size="sm" variant="destructive">
                    Delete
                  </Button>
                }
              />
            )}
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={onClose}
                disabled={create.isPending || update.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={create.isPending || update.isPending}>
                {mode === "create"
                  ? create.isPending
                    ? "Creating…"
                    : "Create"
                  : update.isPending
                    ? "Saving…"
                    : "Save"}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------- Rule row + dialog ----------

function RuleRow({
  rule,
  channels,
  hostGroups,
  isAdmin,
}: {
  rule: RoutingRule;
  channels: NotificationChannel[];
  hostGroups: { id: string; name: string }[];
  isAdmin: boolean;
}) {
  const [open, setOpen] = useState(false);
  const channelNames = useMemo(() => {
    const by = new Map(channels.map((c) => [c.id, c.name]));
    return rule.channel_ids.map((id) => by.get(id) ?? id.slice(0, 8));
  }, [channels, rule.channel_ids]);
  const groupName = hostGroups.find((g) => g.id === rule.host_group_id)?.name;

  return (
    <>
      <button
        type="button"
        onClick={() => isAdmin && setOpen(true)}
        className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm transition ${
          isAdmin ? "hover:bg-secondary/50" : "cursor-default"
        }`}
      >
        <div className="flex flex-col">
          <span className="font-medium">{rule.name}</span>
          <span className="text-xs text-muted-foreground">
            ≥ {rule.min_severity}
            {rule.rule_kind ? ` · ${rule.rule_kind}` : ""}
            {groupName ? ` · group ${groupName}` : ""}
            {" → "}
            {channelNames.join(", ") || "(no channels)"}
          </span>
        </div>
        <span
          className={`text-[10px] font-medium uppercase tracking-wider ${
            rule.enabled ? "text-emerald-500" : "text-muted-foreground"
          }`}
        >
          {rule.enabled ? "enabled" : "disabled"}
        </span>
      </button>
      {open && (
        <RuleDialog
          mode="edit"
          rule={rule}
          channels={channels}
          hostGroups={hostGroups}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}

interface RuleFormState {
  name: string;
  min_severity: Severity;
  rule_kind: RuleKind | "any";
  host_group_id: string | "any";
  channel_ids: Set<string>;
  enabled: boolean;
}

function ruleFormFrom(rule?: RoutingRule): RuleFormState {
  return {
    name: rule?.name ?? "",
    min_severity: rule?.min_severity ?? "medium",
    rule_kind: rule?.rule_kind ?? "any",
    host_group_id: rule?.host_group_id ?? "any",
    channel_ids: new Set(rule?.channel_ids ?? []),
    enabled: rule?.enabled ?? true,
  };
}

function RuleDialog({
  mode,
  rule,
  channels,
  hostGroups,
  onClose,
}: {
  mode: "create" | "edit";
  rule?: RoutingRule;
  channels: NotificationChannel[];
  hostGroups: { id: string; name: string }[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [form, setForm] = useState<RuleFormState>(() => ruleFormFrom(rule));
  const [error, setError] = useState<string | null>(null);

  const body = () => ({
    name: form.name,
    min_severity: form.min_severity,
    rule_kind: form.rule_kind === "any" ? null : form.rule_kind,
    host_group_id: form.host_group_id === "any" ? null : form.host_group_id,
    channel_ids: Array.from(form.channel_ids),
    enabled: form.enabled,
  });

  const create = useMutation({
    mutationFn: () => routingApi.create(body()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["routing-rules"] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail : String(e)),
  });
  const update = useMutation({
    mutationFn: () => {
      if (!rule) throw new Error("no rule");
      return routingApi.update(rule.id, body());
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["routing-rules"] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail : String(e)),
  });
  const remove = useMutation({
    mutationFn: () => {
      if (!rule) throw new Error("no rule");
      return routingApi.remove(rule.id);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["routing-rules"] });
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail : String(e)),
  });

  const toggle = (id: string) => {
    setForm((f) => {
      const next = new Set(f.channel_ids);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return { ...f, channel_ids: next };
    });
  };

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{mode === "create" ? "New routing rule" : `Edit ${rule?.name}`}</DialogTitle>
        </DialogHeader>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            if (mode === "create") create.mutate();
            else update.mutate();
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="r-name">Name</Label>
            <Input
              id="r-name"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              required
              maxLength={128}
            />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-2">
              <Label htmlFor="r-sev">Min severity</Label>
              <Select
                id="r-sev"
                value={form.min_severity}
                onChange={(e) =>
                  setForm((f) => ({ ...f, min_severity: e.target.value as Severity }))
                }
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="r-kind">Rule kind</Label>
              <Select
                id="r-kind"
                value={form.rule_kind}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    rule_kind: e.target.value as RuleKind | "any",
                  }))
                }
              >
                <option value="any">any</option>
                {RULE_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="r-status">Status</Label>
              <Select
                id="r-status"
                value={form.enabled ? "enabled" : "disabled"}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.value === "enabled" }))}
              >
                <option value="enabled">enabled</option>
                <option value="disabled">disabled</option>
              </Select>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="r-group">Host group (optional)</Label>
            <Select
              id="r-group"
              value={form.host_group_id}
              onChange={(e) => setForm((f) => ({ ...f, host_group_id: e.target.value }))}
            >
              <option value="any">any host</option>
              {hostGroups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Channels</Label>
            {channels.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                Create a channel first — a rule with no channels never fires.
              </p>
            ) : (
              <ul className="space-y-1">
                {channels.map((c) => (
                  <li key={c.id} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id={`r-ch-${c.id}`}
                      checked={form.channel_ids.has(c.id)}
                      onChange={() => toggle(c.id)}
                    />
                    <label htmlFor={`r-ch-${c.id}`} className="cursor-pointer text-sm">
                      {c.name}
                      <span className="ml-2 text-xs text-muted-foreground">{c.kind}</span>
                    </label>
                  </li>
                ))}
              </ul>
            )}
          </div>
          {error && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          <DialogFooter className="flex items-center justify-between">
            {mode === "edit" && rule && (
              <ConfirmDestructive
                title="Delete routing rule?"
                description={
                  <>
                    <span className="font-mono">{rule.name}</span> will be removed. Channels keep
                    working; they just won&apos;t be selected by this rule.
                  </>
                }
                confirmLabel="Yes, delete"
                onConfirm={() => remove.mutate()}
                pending={remove.isPending}
                trigger={
                  <Button type="button" size="sm" variant="destructive">
                    Delete
                  </Button>
                }
              />
            )}
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={onClose}
                disabled={create.isPending || update.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={create.isPending || update.isPending}>
                {mode === "create"
                  ? create.isPending
                    ? "Creating…"
                    : "Create"
                  : update.isPending
                    ? "Saving…"
                    : "Save"}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------- helpers ----------

function parseJsonOrThrow(raw: string): Record<string, unknown> {
  try {
    const v = JSON.parse(raw);
    if (typeof v !== "object" || v === null || Array.isArray(v))
      throw new Error("must be a JSON object");
    return v as Record<string, unknown>;
  } catch (e) {
    throw new Error(`invalid JSON: ${(e as Error).message}`);
  }
}
