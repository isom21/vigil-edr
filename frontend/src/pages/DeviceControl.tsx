/**
 * Device control / USB block policies (Phase 3 #3.10).
 *
 * Admin-only writes; analyst+ can read. Each policy targets either a
 * specific host group or the global default (NULL = applies to every
 * host). The agent applies via udev (Linux) or DeviceInstall registry
 * (Windows). Mutations fan out a `DEVICE_CONTROL_SYNC` command per
 * affected host.
 */
import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { deviceControlApi } from "@/api/device_control";
import { hostGroupsApi } from "@/api/hostGroups";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/useAuth";
import type { DevicePolicyKind } from "@/types/api";

const KIND_LABELS: Record<DevicePolicyKind, string> = {
  usb_block: "Block all USB",
  usb_read_only: "Read-only USB",
  usb_allow_only: "Allow-listed VID/PID only",
};

function splitList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function DeviceControl() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const list = useQuery({
    queryKey: ["device-policies"],
    queryFn: () => deviceControlApi.list(),
    refetchInterval: 30_000,
  });
  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => hostGroupsApi.list({ limit: 200 }),
    enabled: isAdmin,
  });

  const [name, setName] = useState("");
  const [kind, setKind] = useState<DevicePolicyKind>("usb_block");
  const [hostGroupId, setHostGroupId] = useState<string>("");
  const [vids, setVids] = useState("");
  const [pids, setPids] = useState("");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      deviceControlApi.create({
        name: name.trim(),
        kind,
        host_group_id: hostGroupId || null,
        allowed_vendor_ids: splitList(vids),
        allowed_product_ids: splitList(pids),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["device-policies"] });
      setName("");
      setVids("");
      setPids("");
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => deviceControlApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["device-policies"] }),
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      deviceControlApi.update(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["device-policies"] }),
  });

  if (!isAdmin && (list.data?.length ?? 0) === 0) {
    return (
      <>
        <PageHeader title="Device control" />
        <div className="p-8 text-sm text-muted-foreground">No policies.</div>
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
        title="Device control"
        description={`${list.data?.length ?? 0} policies · enforced via udev (Linux) and DeviceInstall (Windows).`}
      />
      <div className="space-y-4 px-8 py-6">
        {isAdmin && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Add policy</CardTitle>
            </CardHeader>
            <CardContent>
              <form className="grid grid-cols-1 gap-3 md:grid-cols-2" onSubmit={onCreate}>
                <div>
                  <Label htmlFor="dc-name">Name</Label>
                  <Input
                    id="dc-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="No USB on finance laptops"
                    autoComplete="off"
                  />
                </div>
                <div>
                  <Label htmlFor="dc-kind">Kind</Label>
                  <select
                    id="dc-kind"
                    value={kind}
                    onChange={(e) => setKind(e.target.value as DevicePolicyKind)}
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
                  <Label htmlFor="dc-group">Host group</Label>
                  <select
                    id="dc-group"
                    value={hostGroupId}
                    onChange={(e) => setHostGroupId(e.target.value)}
                    className="block w-full rounded-md border px-3 py-2 text-sm"
                  >
                    <option value="">Global (every host)</option>
                    {groups.data?.items.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div />
                <div>
                  <Label htmlFor="dc-vids">Allowed vendor IDs (VID, hex)</Label>
                  <Input
                    id="dc-vids"
                    value={vids}
                    onChange={(e) => setVids(e.target.value)}
                    placeholder="046d, 04f9"
                    autoComplete="off"
                  />
                </div>
                <div>
                  <Label htmlFor="dc-pids">Allowed product IDs (PID, hex)</Label>
                  <Input
                    id="dc-pids"
                    value={pids}
                    onChange={(e) => setPids(e.target.value)}
                    placeholder="c52b, 0123"
                    autoComplete="off"
                  />
                </div>
                <div className="md:col-span-2">
                  <Button type="submit" size="sm" disabled={create.isPending}>
                    <Plus className="h-3.5 w-3.5" aria-hidden="true" /> Add policy
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
            <CardTitle className="text-base">Policies</CardTitle>
          </CardHeader>
          <CardContent>
            {list.isLoading && <p className="text-sm text-muted-foreground">Loading policies…</p>}
            {!list.isLoading && (list.data?.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground">No device control policies yet.</p>
            )}
            <ul className="divide-y divide-border">
              {list.data?.map((policy) => (
                <li key={policy.id} className="flex items-center justify-between py-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{policy.name}</span>
                      <span className="rounded-sm bg-secondary px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                        {KIND_LABELS[policy.kind]}
                      </span>
                      {!policy.enabled && (
                        <span className="rounded-sm bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wider">
                          disabled
                        </span>
                      )}
                      {policy.host_group_id && (
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                          group-scoped
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {policy.allowed_vendor_ids.length} VID · {policy.allowed_product_ids.length}{" "}
                      PID
                    </div>
                  </div>
                  {isAdmin && (
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => toggle.mutate({ id: policy.id, enabled: !policy.enabled })}
                        disabled={toggle.isPending}
                      >
                        {policy.enabled ? "Disable" : "Enable"}
                      </Button>
                      <ConfirmDestructive
                        title="Delete policy?"
                        description={
                          <>
                            <span className="font-medium">{policy.name}</span> will be removed from
                            every host within seconds.
                          </>
                        }
                        confirmLabel="Yes, delete"
                        onConfirm={() => remove.mutate(policy.id)}
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
