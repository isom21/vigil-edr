/**
 * SIEM forwarders (Phase 1 #1.5).
 *
 * Admin-only. Operators register one or more SIEM destinations
 * (syslog/CEF, Splunk HEC, Microsoft Sentinel via Event Hub); the
 * forwarder worker consumes telemetry.normalized + alerts.raw and
 * fans every event out to each enabled destination.
 *
 * The list view mirrors Users.tsx — table on the left, "New
 * destination" dialog opened from the top-right action. Edit-in-place
 * lives in a per-row drawer; the destination's secrets are never
 * echoed back from the server, so changing a credential requires
 * re-entering the full config.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { siemApi } from "@/api/siem";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAuth } from "@/hooks/useAuth";
import type { SiemDestination, SiemKind } from "@/types/api";

const KIND_LABEL: Record<SiemKind, string> = {
  syslog_cef: "Syslog / CEF",
  splunk_hec: "Splunk HEC",
  sentinel_hub: "Sentinel Event Hub",
};

const KIND_ORDER: SiemKind[] = ["syslog_cef", "splunk_hec", "sentinel_hub"];

/** Per-kind config form layout. Order is significant — the form
 * renders fields in declaration order. */
interface FieldSpec {
  key: string;
  label: string;
  placeholder?: string;
  secret?: boolean;
  type?: "text" | "number" | "select";
  options?: string[];
  required?: boolean;
  hint?: string;
}

const FIELDS_BY_KIND: Record<SiemKind, FieldSpec[]> = {
  syslog_cef: [
    { key: "host", label: "Host", required: true, placeholder: "siem.example.com" },
    { key: "port", label: "Port", required: true, type: "number", placeholder: "514" },
    {
      key: "protocol",
      label: "Protocol",
      type: "select",
      options: ["udp", "tcp", "tls"],
    },
    { key: "vendor", label: "CEF DeviceVendor", placeholder: "Vigil" },
    { key: "product", label: "CEF DeviceProduct", placeholder: "EDR" },
  ],
  splunk_hec: [
    {
      key: "url",
      label: "Collector URL",
      required: true,
      placeholder: "https://splunk.example.com:8088",
    },
    {
      key: "token",
      label: "HEC token",
      required: true,
      secret: true,
      placeholder: "ABCDEFGH-1234-5678-9ABC-DEF012345678",
    },
    { key: "index", label: "Index", placeholder: "main" },
    { key: "sourcetype", label: "Sourcetype", placeholder: "vigil:telemetry" },
  ],
  sentinel_hub: [
    {
      key: "namespace",
      label: "Namespace",
      required: true,
      placeholder: "myhub.servicebus.windows.net",
    },
    { key: "hub", label: "Event Hub name", required: true, placeholder: "vigil-events" },
    {
      key: "sas_key_name",
      label: "SAS key name",
      required: true,
      placeholder: "RootManageSharedAccessKey",
    },
    {
      key: "sas_key",
      label: "SAS key",
      required: true,
      secret: true,
      hint: "Never echoed back; re-enter to rotate.",
    },
  ],
};

export function SiemForwarders() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const list = useQuery({
    queryKey: ["siem-destinations"],
    queryFn: siemApi.list,
    refetchInterval: 15_000,
  });

  const [createOpen, setCreateOpen] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);

  const openEdit = useMemo(
    () => list.data?.find((d) => d.id === editId) ?? null,
    [editId, list.data],
  );

  const toggleEnabled = useMutation({
    mutationFn: (d: SiemDestination) => siemApi.update(d.id, { enabled: !d.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["siem-destinations"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => siemApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["siem-destinations"] }),
  });

  if (!isAdmin) {
    return (
      <>
        <PageHeader title="SIEM forwarders" />
        <div className="p-8 text-sm text-muted-foreground">SIEM destinations are admin-only.</div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="SIEM forwarders"
        description={`${list.data?.length ?? 0} destination${(list.data?.length ?? 0) === 1 ? "" : "s"} · forwarder fans telemetry + alerts to each enabled sink.`}
        actions={
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            New destination
          </Button>
        }
      />
      <div className="space-y-4 px-8 py-6">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Destinations</CardTitle>
          </CardHeader>
          <CardContent>
            {list.isLoading && (
              <p className="text-sm text-muted-foreground">Loading destinations…</p>
            )}
            {!list.isLoading && (list.data?.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground">
                No destinations registered yet. Click{" "}
                <span className="font-mono">New destination</span> to add one.
              </p>
            )}
            <ul className="divide-y divide-border">
              {list.data?.map((d) => (
                <li key={d.id} className="flex items-center justify-between py-3">
                  <div
                    className="flex-1 cursor-pointer"
                    onClick={() => setEditId(d.id)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") setEditId(d.id);
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{d.name}</span>
                      <span className="rounded-sm bg-secondary px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                        {KIND_LABEL[d.kind]}
                      </span>
                      {d.enabled ? (
                        <span className="text-[10px] uppercase tracking-wider text-emerald-500">
                          enabled
                        </span>
                      ) : (
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                          disabled
                        </span>
                      )}
                      {d.error_count > 0 && (
                        <span className="text-[10px] uppercase tracking-wider text-destructive">
                          {d.error_count} error{d.error_count === 1 ? "" : "s"}
                        </span>
                      )}
                    </div>
                    <div className="text-xs tabular-nums text-muted-foreground">
                      lag {d.lag_seconds.toFixed(1)}s · last send{" "}
                      {d.last_send_at ? new Date(d.last_send_at).toLocaleString() : "—"}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => toggleEnabled.mutate(d)}
                      disabled={toggleEnabled.isPending}
                    >
                      {d.enabled ? "Disable" : "Enable"}
                    </Button>
                    <ConfirmDestructive
                      title="Delete destination?"
                      description={
                        <>
                          <span className="font-mono">{d.name}</span> will be removed. The forwarder
                          stops emitting to it within seconds.
                        </>
                      }
                      confirmLabel="Yes, delete"
                      onConfirm={() => remove.mutate(d.id)}
                      pending={remove.isPending}
                      trigger={
                        <Button size="sm" variant="destructive">
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        </Button>
                      }
                    />
                  </div>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      {createOpen && (
        <DestinationDialog
          mode="create"
          onClose={() => setCreateOpen(false)}
          onSuccess={() => {
            setCreateOpen(false);
            qc.invalidateQueries({ queryKey: ["siem-destinations"] });
          }}
        />
      )}
      {openEdit && (
        <DestinationDialog
          mode="edit"
          destination={openEdit}
          onClose={() => setEditId(null)}
          onSuccess={() => {
            setEditId(null);
            qc.invalidateQueries({ queryKey: ["siem-destinations"] });
          }}
        />
      )}
    </>
  );
}

function DestinationDialog({
  mode,
  destination,
  onClose,
  onSuccess,
}: {
  mode: "create" | "edit";
  destination?: SiemDestination;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState(destination?.name ?? "");
  const [kind, setKind] = useState<SiemKind>(destination?.kind ?? "syslog_cef");
  const [enabled, setEnabled] = useState(destination?.enabled ?? true);
  const [config, setConfig] = useState<Record<string, string>>(() => {
    // Pre-populate non-secret fields from the round-tripped (redacted)
    // config. Secrets show as empty so the operator notices they need
    // to be re-entered (the server treats "***" as a secret token but
    // we explicitly empty it to make the affordance clear).
    const out: Record<string, string> = {};
    if (!destination) return out;
    for (const [k, v] of Object.entries(destination.config)) {
      out[k] = v === "***" ? "" : String(v ?? "");
    }
    return out;
  });
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      // Strip empty strings — keys an operator deliberately blanks out
      // are NOT sent. For required secrets that means the server
      // rejects with 400, which is what we want.
      const cleanConfig: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(config)) {
        if (v === "") continue;
        // Numeric coercion for fields the form rendered as type=number.
        const spec = FIELDS_BY_KIND[kind].find((f) => f.key === k);
        if (spec?.type === "number") {
          const n = Number(v);
          if (!Number.isNaN(n)) cleanConfig[k] = n;
          continue;
        }
        cleanConfig[k] = v;
      }
      if (mode === "create") {
        return siemApi.create({ name, kind, enabled, config: cleanConfig });
      }
      if (!destination) throw new Error("destination missing");
      const body: Record<string, unknown> = {};
      if (name !== destination.name) body.name = name;
      if (enabled !== destination.enabled) body.enabled = enabled;
      // PATCH replaces the whole stored blob — only do this if the
      // form actually has values for the required fields (otherwise
      // the server 400s and the operator gets a clear "what changed
      // again?" without losing the existing destination).
      if (Object.keys(cleanConfig).length > 0) body.config = cleanConfig;
      return siemApi.update(destination.id, body);
    },
    onSuccess,
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {mode === "create" ? "New SIEM destination" : `Edit ${destination?.name}`}
          </DialogTitle>
        </DialogHeader>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            mutation.mutate();
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="dest-name">Name</Label>
            <Input
              id="dest-name"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="splunk-prod"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="dest-kind">Kind</Label>
            <Select
              value={kind}
              disabled={mode === "edit"}
              onValueChange={(v) => {
                setKind(v as SiemKind);
                setConfig({});
              }}
            >
              <SelectTrigger id="dest-kind">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {KIND_ORDER.map((k) => (
                  <SelectItem key={k} value={k}>
                    {KIND_LABEL[k]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {mode === "edit" && (
              <p className="text-[11px] text-muted-foreground">
                Kind can&apos;t change after creation. Delete and re-add to switch sinks.
              </p>
            )}
          </div>

          {FIELDS_BY_KIND[kind].map((spec) => (
            <div key={spec.key} className="space-y-2">
              <Label htmlFor={`dest-cfg-${spec.key}`}>
                {spec.label}
                {spec.required && <span className="text-destructive"> *</span>}
              </Label>
              {spec.type === "select" ? (
                <Select
                  value={config[spec.key] ?? spec.options?.[0] ?? ""}
                  onValueChange={(v) => setConfig((prev) => ({ ...prev, [spec.key]: v }))}
                >
                  <SelectTrigger id={`dest-cfg-${spec.key}`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {spec.options?.map((opt) => (
                      <SelectItem key={opt} value={opt}>
                        {opt}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  id={`dest-cfg-${spec.key}`}
                  type={spec.secret ? "password" : spec.type === "number" ? "number" : "text"}
                  required={spec.required && mode === "create"}
                  value={config[spec.key] ?? ""}
                  placeholder={spec.placeholder}
                  onChange={(e) => setConfig((prev) => ({ ...prev, [spec.key]: e.target.value }))}
                />
              )}
              {spec.hint && <p className="text-[11px] text-muted-foreground">{spec.hint}</p>}
            </div>
          ))}

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="dest-enabled"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <Label htmlFor="dest-enabled" className="cursor-pointer">
              Enabled
            </Label>
          </div>

          {error && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={mutation.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending
                ? mode === "create"
                  ? "Creating…"
                  : "Saving…"
                : mode === "create"
                  ? "Create destination"
                  : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
