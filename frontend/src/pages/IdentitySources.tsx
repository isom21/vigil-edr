/**
 * Identity threat detection sources (Phase 4 #4.3).
 *
 * Admin-only. Operators register Okta + Azure AD integrations; the
 * monitor worker polls each on its cadence, runs the impossible-
 * travel / brute-force / MFA-bombing / password-spray detectors, and
 * emits alerts under synthetic Rules.
 *
 * Same JSON-textarea config shape as `/case-destinations` — the
 * required keys differ per provider but operators may add provider-
 * specific extras (Okta custom domains, Azure cloud routing) without
 * the form pinning them down.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { identityApi } from "@/api/identity";
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
import type { IdentitySource, IdentitySourceKind } from "@/types/api";

const KIND_LABEL: Record<IdentitySourceKind, string> = {
  okta: "Okta",
  azure_ad: "Azure AD",
};

const KIND_ORDER: IdentitySourceKind[] = ["okta", "azure_ad"];

const PLACEHOLDER_BY_KIND: Record<IdentitySourceKind, string> = {
  okta: JSON.stringify(
    {
      domain: "example.okta.com",
      api_token: "<Okta SSWS API token>",
    },
    null,
    2,
  ),
  azure_ad: JSON.stringify(
    {
      tenant_id: "<azure-tenant-uuid>",
      client_id: "<app-registration-client-id>",
      client_secret: "<app-registration-secret>",
    },
    null,
    2,
  ),
};

export function IdentitySources() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const list = useQuery({
    queryKey: ["identity-sources"],
    queryFn: identityApi.list,
    refetchInterval: 30_000,
  });

  const [createOpen, setCreateOpen] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);

  const openEdit = useMemo(
    () => list.data?.find((d) => d.id === editId) ?? null,
    [editId, list.data],
  );

  const toggleEnabled = useMutation({
    mutationFn: (s: IdentitySource) => identityApi.update(s.id, { enabled: !s.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["identity-sources"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => identityApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["identity-sources"] }),
  });

  if (!isAdmin) {
    return (
      <>
        <PageHeader title="Identity sources" />
        <div className="p-8 text-sm text-muted-foreground">Identity sources are admin-only.</div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Identity sources"
        description={`${list.data?.length ?? 0} source${
          (list.data?.length ?? 0) === 1 ? "" : "s"
        } · the monitor worker polls each every few minutes and runs identity-threat detectors against the fetched events.`}
        actions={
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            New source
          </Button>
        }
      />
      <div className="space-y-4 px-8 py-6">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Sources</CardTitle>
          </CardHeader>
          <CardContent>
            {list.isLoading && <p className="text-sm text-muted-foreground">Loading sources…</p>}
            {!list.isLoading && (list.data?.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground">
                No identity sources registered yet. Click{" "}
                <span className="font-mono">New source</span> to add Okta or Azure AD.
              </p>
            )}
            <ul className="divide-y divide-border">
              {list.data?.map((s) => (
                <li key={s.id} className="flex items-center justify-between py-3">
                  <div
                    className="flex-1 cursor-pointer"
                    onClick={() => setEditId(s.id)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") setEditId(s.id);
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{s.name}</span>
                      <span className="rounded-sm bg-secondary px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                        {KIND_LABEL[s.kind]}
                      </span>
                      {s.enabled ? (
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
                      last poll{" "}
                      {s.last_polled_at ? new Date(s.last_polled_at).toLocaleString() : "never"}
                      {" · "}
                      latest event{" "}
                      {s.last_event_ts ? new Date(s.last_event_ts).toLocaleString() : "—"}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => toggleEnabled.mutate(s)}
                      disabled={toggleEnabled.isPending}
                    >
                      {s.enabled ? "Disable" : "Enable"}
                    </Button>
                    <ConfirmDestructive
                      title="Delete identity source?"
                      description={
                        <>
                          <span className="font-mono">{s.name}</span> will be removed. Existing
                          alerts produced from this source remain on the alerts table, but no
                          further polls fire.
                        </>
                      }
                      confirmLabel="Yes, delete"
                      onConfirm={() => remove.mutate(s.id)}
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
        <SourceDialog
          mode="create"
          onClose={() => setCreateOpen(false)}
          onSuccess={() => {
            setCreateOpen(false);
            qc.invalidateQueries({ queryKey: ["identity-sources"] });
          }}
        />
      )}
      {openEdit && (
        <SourceDialog
          mode="edit"
          source={openEdit}
          onClose={() => setEditId(null)}
          onSuccess={() => {
            setEditId(null);
            qc.invalidateQueries({ queryKey: ["identity-sources"] });
          }}
        />
      )}
    </>
  );
}

function SourceDialog({
  mode,
  source,
  onClose,
  onSuccess,
}: {
  mode: "create" | "edit";
  source?: IdentitySource;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState(source?.name ?? "");
  const [kind, setKind] = useState<IdentitySourceKind>(source?.kind ?? "okta");
  const [enabled, setEnabled] = useState(source?.enabled ?? true);
  // Same JSON-textarea convention as case destinations — the stored
  // ciphertext never round-trips, so the textarea starts empty on
  // edit and operators paste a full replacement to rotate.
  const [configText, setConfigText] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      let parsed: Record<string, string> | undefined;
      if (configText.trim()) {
        try {
          parsed = JSON.parse(configText) as Record<string, string>;
        } catch (exc) {
          throw new Error(`config is not valid JSON: ${(exc as Error).message}`);
        }
      }
      if (mode === "create") {
        if (!parsed) throw new Error("config is required");
        return identityApi.create({ name, kind, enabled, config: parsed });
      }
      if (!source) throw new Error("source missing");
      const body: {
        name?: string;
        enabled?: boolean;
        config?: Record<string, string>;
      } = {};
      if (name !== source.name) body.name = name;
      if (enabled !== source.enabled) body.enabled = enabled;
      if (parsed) body.config = parsed;
      return identityApi.update(source.id, body);
    },
    onSuccess,
    onError: (err) => setError(err instanceof ApiError ? err.detail : (err as Error).message),
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {mode === "create" ? "New identity source" : `Edit ${source?.name}`}
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
            <Label htmlFor="identity-name">Name</Label>
            <Input
              id="identity-name"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="okta-prod"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="identity-kind">Kind</Label>
            <Select
              id="identity-kind"
              value={kind}
              disabled={mode === "edit"}
              onChange={(e) => setKind(e.target.value as IdentitySourceKind)}
            >
              {KIND_ORDER.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABEL[k]}
                </option>
              ))}
            </Select>
            {mode === "edit" && (
              <p className="text-[11px] text-muted-foreground">
                Kind can&apos;t change after creation. Delete and re-add to switch providers.
              </p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="identity-config">Config (JSON)</Label>
            <textarea
              id="identity-config"
              className="min-h-[180px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              placeholder={PLACEHOLDER_BY_KIND[kind]}
              spellCheck={false}
            />
            <p className="text-[11px] text-muted-foreground">
              {mode === "edit"
                ? "Stored credentials are never echoed back — leave empty to keep the existing config, or paste a full replacement to rotate."
                : "Paste the source config as a JSON object. Required fields differ per provider; see the placeholder for the shape."}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="identity-enabled"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <Label htmlFor="identity-enabled" className="cursor-pointer">
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
                  ? "Create source"
                  : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
