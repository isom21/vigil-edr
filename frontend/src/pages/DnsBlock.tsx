/**
 * DNS sinkhole / domain block list (Phase 2 #2.12).
 *
 * Admin-only writes; analyst+ can read. Each entry is a domain
 * disposition (block or sinkhole) optionally scoped to a host group
 * (NULL = global). Mutations fan out a `DNS_BLOCK_SYNC` command per
 * affected host so the agent's kernel-side map converges within
 * seconds.
 */
import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { dnsBlockApi } from "@/api/dns_block";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/useAuth";
import type { DnsBlockAction } from "@/types/api";

export function DnsBlock() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const list = useQuery({
    queryKey: ["dns-blocks"],
    queryFn: () => dnsBlockApi.list(),
    refetchInterval: 30_000,
  });

  const [newDomain, setNewDomain] = useState("");
  const [newAction, setNewAction] = useState<DnsBlockAction>("block");
  const [bulkText, setBulkText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => dnsBlockApi.create({ domain: newDomain.trim(), action: newAction }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-blocks"] });
      setNewDomain("");
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => dnsBlockApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-blocks"] }),
  });

  const bulkImport = useMutation({
    mutationFn: () => {
      const domains = bulkText
        .split(/\s+/)
        .map((s) => s.trim())
        .filter(Boolean);
      return dnsBlockApi.bulkImport({ action: newAction, domains });
    },
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["dns-blocks"] });
      setBulkText("");
      setError(`Imported ${result.inserted} (skipped ${result.skipped})`);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  if (!isAdmin && (list.data?.length ?? 0) === 0) {
    return (
      <>
        <PageHeader title="DNS block list" />
        <div className="p-8 text-sm text-muted-foreground">No entries.</div>
      </>
    );
  }

  function onCreate(e: FormEvent) {
    e.preventDefault();
    if (!newDomain.trim()) return;
    create.mutate();
  }

  function onBulkImport(e: FormEvent) {
    e.preventDefault();
    if (!bulkText.trim()) return;
    bulkImport.mutate();
  }

  return (
    <>
      <PageHeader
        title="DNS block list"
        description={`${list.data?.length ?? 0} entries · enforced kernel-side on every agent.`}
      />
      <div className="space-y-4 px-8 py-6">
        {isAdmin && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Add entry</CardTitle>
            </CardHeader>
            <CardContent>
              <form className="flex items-end gap-3" onSubmit={onCreate}>
                <div className="flex-1">
                  <Label htmlFor="dns-domain">Domain</Label>
                  <Input
                    id="dns-domain"
                    value={newDomain}
                    onChange={(e) => setNewDomain(e.target.value)}
                    placeholder="evil.example.com"
                    autoComplete="off"
                  />
                </div>
                <div>
                  <Label htmlFor="dns-action">Action</Label>
                  <select
                    id="dns-action"
                    value={newAction}
                    onChange={(e) => setNewAction(e.target.value as DnsBlockAction)}
                    className="block rounded-md border px-3 py-2 text-sm"
                  >
                    <option value="block">Block</option>
                    <option value="sinkhole">Sinkhole</option>
                  </select>
                </div>
                <Button type="submit" size="sm" disabled={create.isPending}>
                  <Plus className="h-3.5 w-3.5" aria-hidden="true" /> Add
                </Button>
              </form>

              <form className="mt-6 space-y-2" onSubmit={onBulkImport}>
                <Label htmlFor="dns-bulk">Bulk import (one domain per line)</Label>
                <textarea
                  id="dns-bulk"
                  value={bulkText}
                  onChange={(e) => setBulkText(e.target.value)}
                  rows={4}
                  className="block w-full rounded-md border px-3 py-2 font-mono text-xs"
                />
                <Button
                  type="submit"
                  size="sm"
                  variant="outline"
                  disabled={bulkImport.isPending || !bulkText.trim()}
                >
                  Import
                </Button>
              </form>
              {error && (
                <div className="mt-3 rounded-md bg-destructive/10 px-3 py-2 text-sm">{error}</div>
              )}
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Entries</CardTitle>
          </CardHeader>
          <CardContent>
            {list.isLoading && <p className="text-sm text-muted-foreground">Loading entries…</p>}
            {!list.isLoading && (list.data?.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground">No DNS block entries yet.</p>
            )}
            <ul className="divide-y divide-border">
              {list.data?.map((entry) => (
                <li key={entry.id} className="flex items-center justify-between py-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm">{entry.domain}</span>
                      <span className="rounded-sm bg-secondary px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                        {entry.action}
                      </span>
                      {entry.host_group_id && (
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                          group-scoped
                        </span>
                      )}
                    </div>
                    <div className="text-xs tabular-nums text-muted-foreground">
                      {entry.hits} hits ·{" "}
                      {entry.last_hit_at
                        ? new Date(entry.last_hit_at).toLocaleString()
                        : "never matched"}
                    </div>
                  </div>
                  {isAdmin && (
                    <ConfirmDestructive
                      title="Delete entry?"
                      description={
                        <>
                          <span className="font-mono">{entry.domain}</span> will be removed from
                          every host within seconds.
                        </>
                      }
                      confirmLabel="Yes, delete"
                      onConfirm={() => remove.mutate(entry.id)}
                      pending={remove.isPending}
                      trigger={
                        <Button size="sm" variant="destructive">
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        </Button>
                      }
                    />
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
