/**
 * Network sandbox / detonation (Phase 4 #4.4).
 *
 * Admin-only. Two panels:
 *   * Providers — register Cuckoo (today) or VMRay / ANY.RUN (stubs)
 *     instances. Same JSON-config-in-textarea shape as case_destinations.
 *   * Jobs — recent submissions with their verdict. Manual submit
 *     dialog lets an admin push a sha256 (and optionally a base64
 *     sample blob) into the queue.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, RefreshCcw, Send, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { detonationApi } from "@/api/detonation";
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
import type {
  DetonationJob,
  DetonationJobStatus,
  DetonationProvider,
  DetonationProviderKind,
} from "@/types/api";

const KIND_LABEL: Record<DetonationProviderKind, string> = {
  cuckoo: "Cuckoo",
  vmray: "VMRay",
  anyrun: "ANY.RUN",
};

const KIND_ORDER: DetonationProviderKind[] = ["cuckoo", "vmray", "anyrun"];

const PLACEHOLDER_BY_KIND: Record<DetonationProviderKind, string> = {
  cuckoo: JSON.stringify(
    {
      base_url: "http://cuckoo.local:8090",
      api_token: "<optional bearer token>",
    },
    null,
    2,
  ),
  vmray: JSON.stringify(
    {
      base_url: "https://cloud.vmray.com",
      api_token: "<paid API token>",
    },
    null,
    2,
  ),
  anyrun: JSON.stringify(
    {
      base_url: "https://any.run/api",
      api_token: "<paid API token>",
    },
    null,
    2,
  ),
};

const STATUS_TONE: Record<DetonationJobStatus, string> = {
  queued: "text-muted-foreground",
  running: "text-sky-500",
  verdict: "text-emerald-500",
  failed: "text-destructive",
};

export function Detonation() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const providers = useQuery({
    queryKey: ["detonation-providers"],
    queryFn: detonationApi.listProviders,
    refetchInterval: 30_000,
    enabled: isAdmin,
  });

  const jobs = useQuery({
    queryKey: ["detonation-jobs"],
    queryFn: () => detonationApi.listJobs({ limit: 100 }),
    refetchInterval: 5_000,
    enabled: isAdmin,
  });

  const [createOpen, setCreateOpen] = useState(false);
  const [submitOpen, setSubmitOpen] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);

  const openEdit = useMemo(
    () => providers.data?.find((p) => p.id === editId) ?? null,
    [editId, providers.data],
  );

  const toggleEnabled = useMutation({
    mutationFn: (p: DetonationProvider) =>
      detonationApi.updateProvider(p.id, { enabled: !p.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["detonation-providers"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => detonationApi.removeProvider(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["detonation-providers"] }),
  });

  if (!isAdmin) {
    return (
      <>
        <PageHeader title="Detonation" />
        <div className="p-8 text-sm text-muted-foreground">Detonation is admin-only.</div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Detonation"
        description={`${providers.data?.length ?? 0} provider${
          (providers.data?.length ?? 0) === 1 ? "" : "s"
        } · ${
          jobs.data?.total ?? 0
        } job${jobs.data?.total === 1 ? "" : "s"} · malicious verdicts auto-feed the IOC list.`}
        actions={
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => setSubmitOpen(true)}>
              <Send className="h-3.5 w-3.5" aria-hidden="true" />
              Submit hash
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              New provider
            </Button>
          </div>
        }
      />
      <div className="space-y-4 px-8 py-6">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Providers</CardTitle>
          </CardHeader>
          <CardContent>
            {providers.isLoading && (
              <p className="text-sm text-muted-foreground">Loading providers…</p>
            )}
            {!providers.isLoading && (providers.data?.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground">
                No providers registered yet. Click <span className="font-mono">New provider</span>{" "}
                to add a Cuckoo instance.
              </p>
            )}
            <ul className="divide-y divide-border">
              {providers.data?.map((p) => (
                <li key={p.id} className="flex items-center justify-between py-3">
                  <button
                    type="button"
                    className="flex-1 cursor-pointer rounded-md text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    onClick={() => setEditId(p.id)}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{p.name}</span>
                      <span className="rounded-sm bg-secondary px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                        {KIND_LABEL[p.kind]}
                      </span>
                      {p.enabled ? (
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
                      created {new Date(p.created_at).toLocaleString()}
                    </div>
                  </button>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => toggleEnabled.mutate(p)}
                      disabled={toggleEnabled.isPending}
                    >
                      {p.enabled ? "Disable" : "Enable"}
                    </Button>
                    <ConfirmDestructive
                      title="Delete provider?"
                      description={
                        <>
                          <span className="font-mono">{p.name}</span> will be removed. Existing job
                          rows are deleted with it.
                        </>
                      }
                      confirmLabel="Yes, delete"
                      onConfirm={() => remove.mutate(p.id)}
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

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <CardTitle className="text-base">Recent jobs</CardTitle>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => jobs.refetch()}
              disabled={jobs.isFetching}
              title="Refresh now"
            >
              <RefreshCcw className="h-3.5 w-3.5" aria-hidden="true" />
            </Button>
          </CardHeader>
          <CardContent>
            {jobs.isLoading && <p className="text-sm text-muted-foreground">Loading jobs…</p>}
            {!jobs.isLoading && (jobs.data?.items.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground">
                No jobs yet. Submit a sha256 above to drive your first sandbox detonation.
              </p>
            )}
            <table className="w-full text-sm">
              <tbody className="divide-y divide-border">
                {jobs.data?.items.map((j) => (
                  <JobRow key={j.id} job={j} />
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>

      {createOpen && (
        <ProviderDialog
          mode="create"
          onClose={() => setCreateOpen(false)}
          onSuccess={() => {
            setCreateOpen(false);
            qc.invalidateQueries({ queryKey: ["detonation-providers"] });
          }}
        />
      )}
      {openEdit && (
        <ProviderDialog
          mode="edit"
          provider={openEdit}
          onClose={() => setEditId(null)}
          onSuccess={() => {
            setEditId(null);
            qc.invalidateQueries({ queryKey: ["detonation-providers"] });
          }}
        />
      )}
      {submitOpen && (
        <SubmitDialog
          providers={providers.data ?? []}
          onClose={() => setSubmitOpen(false)}
          onSuccess={() => {
            setSubmitOpen(false);
            qc.invalidateQueries({ queryKey: ["detonation-jobs"] });
          }}
        />
      )}
    </>
  );
}

function JobRow({ job }: { job: DetonationJob }) {
  return (
    <tr>
      <td className="py-2 pr-4 font-mono text-xs">
        {job.sha256.slice(0, 12)}
        <span className="text-muted-foreground">…</span>
      </td>
      <td className={`py-2 pr-4 text-xs uppercase tracking-wider ${STATUS_TONE[job.status]}`}>
        {job.status}
      </td>
      <td className="py-2 pr-4 text-xs">
        {job.verdict_label ?? <span className="text-muted-foreground">—</span>}
        {job.verdict_score != null && (
          <span className="ml-1 text-muted-foreground">({job.verdict_score.toFixed(1)})</span>
        )}
      </td>
      <td className="py-2 pr-4 text-xs tabular-nums text-muted-foreground">
        {new Date(job.submitted_at).toLocaleString()}
      </td>
      <td className="py-2 text-xs text-destructive">{job.error ?? ""}</td>
    </tr>
  );
}

function ProviderDialog({
  mode,
  provider,
  onClose,
  onSuccess,
}: {
  mode: "create" | "edit";
  provider?: DetonationProvider;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState(provider?.name ?? "");
  const [kind, setKind] = useState<DetonationProviderKind>(provider?.kind ?? "cuckoo");
  const [enabled, setEnabled] = useState(provider?.enabled ?? true);
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
        return detonationApi.createProvider({ name, kind, enabled, config: parsed });
      }
      if (!provider) throw new Error("provider missing");
      const body: Record<string, unknown> = {};
      if (name !== provider.name) body.name = name;
      if (enabled !== provider.enabled) body.enabled = enabled;
      if (parsed) body.config = parsed;
      return detonationApi.updateProvider(provider.id, body);
    },
    onSuccess,
    onError: (err) => setError(err instanceof ApiError ? err.detail : (err as Error).message),
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {mode === "create" ? "New detonation provider" : `Edit ${provider?.name}`}
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
            <Label htmlFor="det-name">Name</Label>
            <Input
              id="det-name"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="cuckoo-prod"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="det-kind">Kind</Label>
            <Select
              id="det-kind"
              value={kind}
              disabled={mode === "edit"}
              onChange={(e) => setKind(e.target.value as DetonationProviderKind)}
            >
              {KIND_ORDER.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABEL[k]}
                </option>
              ))}
            </Select>
            {kind !== "cuckoo" && (
              <p className="text-[11px] text-amber-500">
                {KIND_LABEL[kind]} is a stub. Submits return a NotImplementedError until the paid
                API is wired up.
              </p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="det-config">Config (JSON)</Label>
            <textarea
              id="det-config"
              className="min-h-[160px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              placeholder={PLACEHOLDER_BY_KIND[kind]}
              spellCheck={false}
            />
            <p className="text-[11px] text-muted-foreground">
              {mode === "edit"
                ? "Stored credentials are never echoed back — leave empty to keep the existing config, or paste a full replacement to rotate."
                : "Paste the provider config as a JSON object. Cuckoo needs base_url; api_token is optional."}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="det-enabled"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <Label htmlFor="det-enabled" className="cursor-pointer">
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
                  ? "Create provider"
                  : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function SubmitDialog({
  providers,
  onClose,
  onSuccess,
}: {
  providers: DetonationProvider[];
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [sha256, setSha256] = useState("");
  const [providerId, setProviderId] = useState<string>("");
  const [sampleB64, setSampleB64] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      detonationApi.submit({
        sha256: sha256.trim().toLowerCase(),
        provider_id: providerId || null,
        sample_b64: sampleB64.trim() || null,
      }),
    onSuccess,
    onError: (err) => setError(err instanceof ApiError ? err.detail : (err as Error).message),
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Submit hash for detonation</DialogTitle>
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
            <Label htmlFor="submit-sha">SHA-256</Label>
            <Input
              id="submit-sha"
              required
              minLength={64}
              maxLength={64}
              pattern="[a-fA-F0-9]{64}"
              value={sha256}
              onChange={(e) => setSha256(e.target.value)}
              placeholder="hex SHA-256 of the sample"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="submit-provider">Provider</Label>
            <Select
              id="submit-provider"
              value={providerId}
              onChange={(e) => setProviderId(e.target.value)}
            >
              <option value="">First enabled provider</option>
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({KIND_LABEL[p.kind]})
                </option>
              ))}
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="submit-sample">Sample bytes (base64, optional)</Label>
            <textarea
              id="submit-sample"
              className="min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
              value={sampleB64}
              onChange={(e) => setSampleB64(e.target.value)}
              spellCheck={false}
              placeholder="Leave empty to let the manager pull from the quarantine bucket"
            />
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
              {mutation.isPending ? "Submitting…" : "Submit"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
