/**
 * Phase 2 #2.8: application allowlist (learn → enforce).
 *
 * Per-host-group flow:
 *
 *   1. Pick a host group from the selector.
 *   2. Flip the group to LEARN. Agents in the group start shipping
 *      observed binary SHA-256s; the manager records them under
 *      ``allowlist_entry`` with ``learned=true``.
 *   3. Review the learned entries. Add anything the operator wants
 *      explicitly approved with the "Add hash" form (creates a row
 *      with ``manual=true`` — the union is what the agent enforces).
 *   4. Flip to ENFORCE. The agent's kernel-side LSM hook starts
 *      denying any exec whose SHA-256 isn't in the synced set.
 *
 * Reads are open to analyst+; mode flips and entry mutations are
 * admin-only and audited server-side.
 */
import * as React from "react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Lock, ShieldCheck, ShieldQuestion, Trash2 } from "lucide-react";

import { allowlistApi } from "@/api/allowlist";
import { ApiError } from "@/api/client";
import { hostGroupsApi } from "@/api/hostGroups";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import type { AllowlistMode } from "@/types/api";

const MODE_DESCRIPTION: Record<AllowlistMode, string> = {
  off: "No enforcement. Existing entries are kept but the agent ignores them.",
  learn:
    "Agents observe every exec and ship the binary SHA-256 upstream. Nothing is denied — use this to build the corpus.",
  enforce:
    "Agents deny exec for any binary whose SHA-256 is not in the synced set. Switch to OFF or LEARN to add coverage.",
};

const MODE_ICON: Record<AllowlistMode, typeof ShieldCheck> = {
  off: ShieldQuestion,
  learn: ShieldQuestion,
  enforce: ShieldCheck,
};

export function Allowlist() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const qc = useQueryClient();

  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => hostGroupsApi.list({ limit: 200 }),
  });

  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  // First-render: auto-pick the first group so the UI doesn't show
  // an empty state on a freshly-loaded page with N groups.
  if (selectedGroupId === null && groups.data && groups.data.items.length > 0) {
    setSelectedGroupId(groups.data.items[0].id);
  }

  const groupId = selectedGroupId;

  const mode = useQuery({
    queryKey: ["allowlist-mode", groupId],
    queryFn: () =>
      groupId ? allowlistApi.getMode(groupId) : Promise.reject(new Error("no group")),
    enabled: !!groupId,
  });

  const entries = useQuery({
    queryKey: ["allowlist-entries", groupId],
    queryFn: () =>
      groupId ? allowlistApi.listEntries(groupId) : Promise.reject(new Error("no group")),
    enabled: !!groupId,
  });

  const [error, setError] = useState<string | null>(null);

  const setMode = useMutation({
    mutationFn: ({ id, m }: { id: string; m: AllowlistMode }) => allowlistApi.setMode(id, m),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["allowlist-mode", groupId] });
      qc.invalidateQueries({ queryKey: ["allowlist-entries", groupId] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const createEntry = useMutation({
    mutationFn: ({ id, sha256, exec_path }: { id: string; sha256: string; exec_path: string }) =>
      allowlistApi.createEntry(id, { sha256, exec_path: exec_path || null }),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["allowlist-entries", groupId] });
      qc.invalidateQueries({ queryKey: ["allowlist-mode", groupId] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const deleteEntry = useMutation({
    mutationFn: ({ id, entryId }: { id: string; entryId: string }) =>
      allowlistApi.deleteEntry(id, entryId),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["allowlist-entries", groupId] });
      qc.invalidateQueries({ queryKey: ["allowlist-mode", groupId] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const [newSha, setNewSha] = useState("");
  const [newPath, setNewPath] = useState("");

  function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!groupId) return;
    const sha = newSha.trim().toLowerCase();
    if (sha.length !== 64) {
      setError("SHA-256 must be 64 hex characters.");
      return;
    }
    createEntry.mutate({ id: groupId, sha256: sha, exec_path: newPath.trim() });
    setNewSha("");
    setNewPath("");
  }

  const currentMode: AllowlistMode = mode.data?.mode ?? "off";
  const ModeIcon = MODE_ICON[currentMode];

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Application allowlist"
        subtitle="Per-host-group SHA-256 corpus. Learn observed binaries, then enforce."
      />

      {error && (
        <div
          role="alert"
          className="rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {error}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Host group</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center gap-4">
          <div className="grow">
            <Label htmlFor="host-group-select">Group</Label>
            <Select
              value={selectedGroupId ?? undefined}
              onValueChange={(v) => setSelectedGroupId(v)}
            >
              <SelectTrigger id="host-group-select" className="w-full max-w-sm">
                <SelectValue placeholder="Choose a host group" />
              </SelectTrigger>
              <SelectContent>
                {groups.data?.items.map((g) => (
                  <SelectItem key={g.id} value={g.id}>
                    {g.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {mode.data && (
            <div className="flex items-center gap-2">
              <ModeIcon className="h-5 w-5" aria-hidden="true" />
              <Badge variant={currentMode === "enforce" ? "destructive" : "secondary"}>
                {currentMode.toUpperCase()}
              </Badge>
              <span className="text-sm text-muted-foreground">{mode.data.entry_count} entries</span>
            </div>
          )}
        </CardContent>
      </Card>

      {groupId && (
        <Card>
          <CardHeader>
            <CardTitle>Mode</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">{MODE_DESCRIPTION[currentMode]}</p>
            <div className="flex gap-2">
              {(["off", "learn", "enforce"] as AllowlistMode[]).map((m) => (
                <Button
                  key={m}
                  variant={m === currentMode ? "default" : "outline"}
                  disabled={!isAdmin || setMode.isPending}
                  onClick={() => setMode.mutate({ id: groupId, m })}
                >
                  {m.toUpperCase()}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {groupId && isAdmin && (
        <Card>
          <CardHeader>
            <CardTitle>Add hash</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleCreate} className="flex flex-wrap items-end gap-3">
              <div className="grow">
                <Label htmlFor="allowlist-sha">SHA-256 (64 hex chars)</Label>
                <Input
                  id="allowlist-sha"
                  value={newSha}
                  onChange={(e) => setNewSha(e.target.value)}
                  placeholder="abcd1234…"
                  pattern="[0-9a-fA-F]{64}"
                  spellCheck={false}
                />
              </div>
              <div className="grow">
                <Label htmlFor="allowlist-path">Path (optional)</Label>
                <Input
                  id="allowlist-path"
                  value={newPath}
                  onChange={(e) => setNewPath(e.target.value)}
                  placeholder="/usr/bin/curl"
                />
              </div>
              <Button type="submit" disabled={createEntry.isPending}>
                Add to allowlist
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      {groupId && (
        <Card>
          <CardHeader>
            <CardTitle>Entries</CardTitle>
          </CardHeader>
          <CardContent>
            {entries.isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
            {entries.data && entries.data.length === 0 && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Lock className="h-4 w-4" aria-hidden="true" />
                No entries yet. Switch the group to LEARN and let the agent observe execs, or add a
                hash by hand above.
              </div>
            )}
            {entries.data && entries.data.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>SHA-256</TableHead>
                    <TableHead>Path</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>First seen</TableHead>
                    <TableHead>Last seen</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {entries.data.map((e) => (
                    <TableRow key={e.id}>
                      <TableCell className="font-mono text-xs">
                        {e.sha256.slice(0, 12)}…{e.sha256.slice(-8)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{e.exec_path ?? "—"}</TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          {e.learned && <Badge variant="secondary">learned</Badge>}
                          {e.manual && <Badge>manual</Badge>}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {e.first_seen ? new Date(e.first_seen).toLocaleString() : "—"}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {e.last_seen ? new Date(e.last_seen).toLocaleString() : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        {isAdmin && (
                          <ConfirmDestructive
                            title="Delete allowlist entry?"
                            description="The agent will resync immediately. If the group is in enforce mode, any host currently running this binary keeps running it — but any future exec will be denied."
                            onConfirm={() => deleteEntry.mutate({ id: groupId, entryId: e.id })}
                          >
                            <Button size="sm" variant="ghost">
                              <Trash2 className="h-4 w-4" aria-hidden="true" />
                              <span className="sr-only">Delete</span>
                            </Button>
                          </ConfirmDestructive>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
