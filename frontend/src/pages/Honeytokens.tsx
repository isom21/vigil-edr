/**
 * Honeytoken decoys (Phase 4 #4.5).
 *
 * Admin-only writes; analyst+ can read. Each decoy targets either a
 * specific host group or the global default (NULL = every host in the
 * tenant). The agent plants the artifact and tags it with the spec id
 * (xattr on Linux, NTFS Alternate Data Stream / registry value name on
 * Windows). Any touch fires a CRITICAL alert via the synthetic
 * HONEYTOKEN_HIT_RULE_ID.
 */
import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { honeytokensApi } from "@/api/honeytokens";
import { hostGroupsApi } from "@/api/hostGroups";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/useAuth";
import type { HoneytokenKind } from "@/types/api";

const KIND_LABELS: Record<HoneytokenKind, string> = {
  fake_file: "Fake file",
  fake_regkey: "Fake registry key (Windows)",
  creds_in_lsass: "Fake credentials (Windows)",
};

/** Base64-encode a UTF-8 string for the JSON payload body. */
function encodePayloadBody(text: string): string {
  if (!text) return "";
  // btoa works on Latin-1; encode to UTF-8 first.
  return btoa(unescape(encodeURIComponent(text)));
}

export function Honeytokens() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const list = useQuery({
    queryKey: ["honeytokens"],
    queryFn: () => honeytokensApi.list(),
    refetchInterval: 30_000,
  });
  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => hostGroupsApi.list({ limit: 200 }),
    enabled: isAdmin,
  });

  const [name, setName] = useState("");
  const [kind, setKind] = useState<HoneytokenKind>("fake_file");
  const [hostGroupId, setHostGroupId] = useState<string>("");
  const [targetPath, setTargetPath] = useState("");
  const [payloadText, setPayloadText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => {
      const payload_json: Record<string, unknown> = {};
      if (payloadText) {
        payload_json.body = encodePayloadBody(payloadText);
      }
      return honeytokensApi.create({
        name: name.trim(),
        kind,
        host_group_id: hostGroupId || null,
        target_path: targetPath.trim() || null,
        payload_json,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["honeytokens"] });
      setName("");
      setTargetPath("");
      setPayloadText("");
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => honeytokensApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["honeytokens"] }),
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      honeytokensApi.update(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["honeytokens"] }),
  });

  if (!isAdmin && (list.data?.length ?? 0) === 0) {
    return (
      <>
        <PageHeader title="Honeytokens" />
        <div className="p-8 text-sm text-muted-foreground">No decoys deployed.</div>
      </>
    );
  }

  function onCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    create.mutate();
  }

  return (
    <>
      <PageHeader
        title="Honeytokens"
        description={`${list.data?.length ?? 0} decoys · any touch fires a CRITICAL alert.`}
      />
      <div className="space-y-4 px-8 py-6">
        {isAdmin && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Deploy decoy</CardTitle>
            </CardHeader>
            <CardContent>
              <form className="grid grid-cols-1 gap-3 md:grid-cols-2" onSubmit={onCreate}>
                <div>
                  <Label htmlFor="ht-name">Name</Label>
                  <Input
                    id="ht-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Decoy AWS credentials"
                    autoComplete="off"
                  />
                </div>
                <div>
                  <Label htmlFor="ht-kind">Kind</Label>
                  <select
                    id="ht-kind"
                    value={kind}
                    onChange={(e) => setKind(e.target.value as HoneytokenKind)}
                    className="block w-full rounded-md border px-3 py-2 text-sm"
                  >
                    {Object.entries(KIND_LABELS).map(([k, label]) => (
                      <option key={k} value={k}>
                        {label}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <Label htmlFor="ht-group">Host group</Label>
                  <select
                    id="ht-group"
                    value={hostGroupId}
                    onChange={(e) => setHostGroupId(e.target.value)}
                    className="block w-full rounded-md border px-3 py-2 text-sm"
                  >
                    <option value="">Global (every host in tenant)</option>
                    {groups.data?.items.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <Label htmlFor="ht-target">Target path</Label>
                  <Input
                    id="ht-target"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                    placeholder={
                      kind === "fake_regkey"
                        ? "HKLM\\SOFTWARE\\Acme\\Decoy"
                        : "/var/lib/secrets/aws.creds"
                    }
                    autoComplete="off"
                  />
                </div>
                <div className="md:col-span-2">
                  <Label htmlFor="ht-payload">Decoy contents</Label>
                  <textarea
                    id="ht-payload"
                    value={payloadText}
                    onChange={(e) => setPayloadText(e.target.value)}
                    placeholder="aws_access_key_id = AKIAFAKE..."
                    className="block w-full rounded-md border px-3 py-2 font-mono text-xs"
                    rows={3}
                  />
                </div>
                <div className="md:col-span-2">
                  <Button type="submit" size="sm" disabled={create.isPending}>
                    <Plus className="h-3.5 w-3.5" aria-hidden="true" /> Deploy decoy
                  </Button>
                </div>
              </form>
              {error && (
                <div className="mt-3 rounded-md bg-destructive/10 px-3 py-2 text-sm">{error}</div>
              )}
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Deployed decoys</CardTitle>
          </CardHeader>
          <CardContent>
            {list.isLoading && <p className="text-sm text-muted-foreground">Loading decoys…</p>}
            {!list.isLoading && (list.data?.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground">No honeytokens yet.</p>
            )}
            <ul className="divide-y divide-border">
              {list.data?.map((token) => (
                <li key={token.id} className="flex items-center justify-between py-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{token.name}</span>
                      <span className="rounded-sm bg-secondary px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                        {KIND_LABELS[token.kind]}
                      </span>
                      {!token.enabled && (
                        <span className="rounded-sm bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wider">
                          disabled
                        </span>
                      )}
                      {token.host_group_id && (
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                          group-scoped
                        </span>
                      )}
                      {token.hit_count > 0 && (
                        <span className="rounded-sm bg-destructive/15 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-destructive">
                          {token.hit_count} hits
                        </span>
                      )}
                    </div>
                    {token.target_path && (
                      <div className="font-mono text-xs text-muted-foreground">
                        {token.target_path}
                      </div>
                    )}
                    <div className="text-xs text-muted-foreground">
                      deployed to {token.deployed_count} host(s)
                    </div>
                  </div>
                  {isAdmin && (
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => toggle.mutate({ id: token.id, enabled: !token.enabled })}
                        disabled={toggle.isPending}
                      >
                        {token.enabled ? "Disable" : "Enable"}
                      </Button>
                      <ConfirmDestructive
                        title="Remove decoy?"
                        description={
                          <>
                            <span className="font-medium">{token.name}</span> will be cleared from
                            every host within seconds.
                          </>
                        }
                        confirmLabel="Yes, remove"
                        onConfirm={() => remove.mutate(token.id)}
                        pending={remove.isPending}
                        trigger={
                          <Button size="sm" variant="destructive">
                            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          </Button>
                        }
                      />
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
