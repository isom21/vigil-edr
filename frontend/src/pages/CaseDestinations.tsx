/**
 * External case-management destinations (Phase 3 #3.6).
 *
 * Admin-only. Operators register one or more Jira / ServiceNow
 * destinations; the alert lifecycle hook mirrors each state
 * transition into every enabled destination, and the case-sync
 * worker polls each tracker on its tick to close the loop on
 * status changes.
 *
 * List + add + edit + delete + test-fire. The config is a JSON
 * textarea rather than a fielded form because operators add
 * tracker-specific extras (assignment_group, custom field
 * overrides) without us having to know the per-instance schema.
 * The fielded form lives on SiemForwarders where the required
 * fields are tightly constrained.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Plus, Send, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { caseApi } from "@/api/case";
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
import { useAuth } from "@/hooks/useAuth";
import type { CaseDestination, CaseDestinationKind, CaseDestinationTestResult } from "@/types/api";

const KIND_LABEL: Record<CaseDestinationKind, string> = {
  jira: "Jira",
  servicenow: "ServiceNow",
};

const KIND_ORDER: CaseDestinationKind[] = ["jira", "servicenow"];

const PLACEHOLDER_BY_KIND: Record<CaseDestinationKind, string> = {
  jira: JSON.stringify(
    {
      base_url: "https://acme.atlassian.net",
      email: "soc@acme.example",
      api_token: "<atlassian API token>",
      project_key: "SEC",
      issue_type: "Task",
    },
    null,
    2,
  ),
  servicenow: JSON.stringify(
    {
      instance_url: "https://acme.service-now.com",
      username: "vigil_integration",
      password: "<sn password>",
      caller_id: "",
      assignment_group: "",
    },
    null,
    2,
  ),
};

export function CaseDestinations() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const list = useQuery({
    queryKey: ["case-destinations"],
    queryFn: caseApi.list,
    refetchInterval: 30_000,
  });

  const [createOpen, setCreateOpen] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{
    id: string;
    result: CaseDestinationTestResult;
  } | null>(null);

  const openEdit = useMemo(
    () => list.data?.find((d) => d.id === editId) ?? null,
    [editId, list.data],
  );

  const toggleEnabled = useMutation({
    mutationFn: (d: CaseDestination) => caseApi.update(d.id, { enabled: !d.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["case-destinations"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => caseApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["case-destinations"] }),
  });

  const test = useMutation({
    mutationFn: (id: string) => caseApi.test(id),
    onSuccess: (result, id) => setTestResult({ id, result }),
  });

  if (!isAdmin) {
    return (
      <>
        <PageHeader title="Case destinations" />
        <div className="p-8 text-sm text-muted-foreground">Case destinations are admin-only.</div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Case destinations"
        description={`${list.data?.length ?? 0} destination${
          (list.data?.length ?? 0) === 1 ? "" : "s"
        } · alerts are mirrored on state transitions; the poller refreshes status every few minutes.`}
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
                    </div>
                    <div className="text-xs tabular-nums text-muted-foreground">
                      created {new Date(d.created_at).toLocaleString()}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => test.mutate(d.id)}
                      disabled={test.isPending}
                      title="Run a dry-run create against this destination"
                    >
                      <Send className="h-3.5 w-3.5" aria-hidden="true" />
                      Test
                    </Button>
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
                          <span className="font-mono">{d.name}</span> will be removed. Existing case
                          links remain on the alerts but no further mirrors fire.
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
            qc.invalidateQueries({ queryKey: ["case-destinations"] });
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
            qc.invalidateQueries({ queryKey: ["case-destinations"] });
          }}
        />
      )}
      {testResult && (
        <Dialog open onOpenChange={(v) => !v && setTestResult(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Test result</DialogTitle>
            </DialogHeader>
            <div className="space-y-2 text-sm">
              {testResult.result.ok ? (
                <>
                  <p className="text-emerald-500">
                    Created test issue{" "}
                    <span className="font-mono">{testResult.result.external_id}</span>
                  </p>
                  {testResult.result.external_url && (
                    <p>
                      <a
                        href={testResult.result.external_url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 underline-offset-2 hover:underline"
                      >
                        Open in tracker
                        <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                      </a>
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    The test issue stays on the tracker — delete it manually once you&apos;ve
                    confirmed the integration.
                  </p>
                </>
              ) : (
                <p className="text-destructive">{testResult.result.error ?? "Failed"}</p>
              )}
            </div>
            <DialogFooter>
              <Button onClick={() => setTestResult(null)}>Close</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
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
  destination?: CaseDestination;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState(destination?.name ?? "");
  const [kind, setKind] = useState<CaseDestinationKind>(destination?.kind ?? "jira");
  const [enabled, setEnabled] = useState(destination?.enabled ?? true);
  // Config is JSON-as-text. The backend rejects malformed JSON at
  // submit time, and we surface that as the API error. On edit, the
  // stored ciphertext never round-trips — the textarea starts empty
  // and the operator re-enters the full config to rotate.
  const [configText, setConfigText] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      let parsed: Record<string, unknown> | undefined;
      if (configText.trim()) {
        try {
          parsed = JSON.parse(configText) as Record<string, unknown>;
        } catch (exc) {
          throw new Error(`config is not valid JSON: ${(exc as Error).message}`);
        }
      }
      if (mode === "create") {
        if (!parsed) throw new Error("config is required");
        return caseApi.create({ name, kind, enabled, config: parsed });
      }
      if (!destination) throw new Error("destination missing");
      const body: Record<string, unknown> = {};
      if (name !== destination.name) body.name = name;
      if (enabled !== destination.enabled) body.enabled = enabled;
      if (parsed) body.config = parsed;
      return caseApi.update(destination.id, body);
    },
    onSuccess,
    onError: (err) => setError(err instanceof ApiError ? err.detail : (err as Error).message),
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {mode === "create" ? "New case destination" : `Edit ${destination?.name}`}
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
            <Label htmlFor="case-name">Name</Label>
            <Input
              id="case-name"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="jira-soc-prod"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="case-kind">Kind</Label>
            <Select
              id="case-kind"
              value={kind}
              disabled={mode === "edit"}
              onChange={(e) => setKind(e.target.value as CaseDestinationKind)}
            >
              {KIND_ORDER.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABEL[k]}
                </option>
              ))}
            </Select>
            {mode === "edit" && (
              <p className="text-[11px] text-muted-foreground">
                Kind can&apos;t change after creation. Delete and re-add to switch trackers.
              </p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="case-config">Config (JSON)</Label>
            <textarea
              id="case-config"
              className="min-h-[180px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              placeholder={PLACEHOLDER_BY_KIND[kind]}
              spellCheck={false}
            />
            <p className="text-[11px] text-muted-foreground">
              {mode === "edit"
                ? "Stored credentials are never echoed back — leave empty to keep the existing config, or paste a full replacement to rotate."
                : "Paste the destination config as a JSON object. Required fields differ per tracker; see the placeholder for the shape."}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="case-enabled"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <Label htmlFor="case-enabled" className="cursor-pointer">
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
