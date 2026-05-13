/**
 * Tenants CRUD (super-admin only) — Phase 3 #3.1.
 *
 * Super-admins use this view to manage the tenant catalog: add a
 * new tenant, rename one, soft-disable it, or delete one once
 * every dependent row has been moved or removed. The backend (see
 * app/api/tenants.py) enforces the same gates server-side; this
 * page is the UI sugar.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { ApiError } from "@/api/client";
import { tenantsApi } from "@/api/tenants";
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
import { useAuth } from "@/hooks/useAuth";
import type { Tenant } from "@/types/api";

export function Tenants() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const [createOpen, setCreateOpen] = useState(false);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["tenants"],
    queryFn: tenantsApi.list,
    enabled: !!user?.is_super_admin,
  });

  const create = useMutation({
    mutationFn: () => tenantsApi.create({ slug, name }),
    onSuccess: () => {
      setCreateOpen(false);
      setSlug("");
      setName("");
      setError(null);
      qc.invalidateQueries({ queryKey: ["tenants"] });
    },
    onError: (e: unknown) => {
      setError(e instanceof ApiError ? e.detail : "create failed");
    },
  });

  const toggleDisabled = useMutation({
    mutationFn: (row: Tenant) => tenantsApi.update(row.id, { disabled: !row.disabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });

  const remove = useMutation({
    mutationFn: (row: Tenant) => tenantsApi.remove(row.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });

  if (!user) return null;
  if (!user.is_super_admin) {
    return (
      <div className="p-6">
        <PageHeader title="Tenants" description="Super-admin only." />
        <div className="text-sm text-muted-foreground">
          This page is only available to super-admins.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Tenants"
        description="Schema-level isolation boundaries. One row per SOC / customer."
        actions={
          <Button onClick={() => setCreateOpen(true)} size="sm">
            <Plus className="mr-1 h-4 w-4" /> New tenant
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>Catalog</CardTitle>
        </CardHeader>
        <CardContent>
          {list.isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
          {list.data && list.data.length === 0 && (
            <div className="text-sm text-muted-foreground">No tenants yet.</div>
          )}
          {list.data && list.data.length > 0 && (
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="py-2">Slug</th>
                  <th className="py-2">Name</th>
                  <th className="py-2">Status</th>
                  <th className="py-2">Created</th>
                  <th className="py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((t) => (
                  <tr key={t.id} className="border-t">
                    <td className="py-2 font-mono text-xs">{t.slug}</td>
                    <td className="py-2">{t.name}</td>
                    <td className="py-2">
                      {t.disabled ? (
                        <span className="text-xs text-amber-500">disabled</span>
                      ) : (
                        <span className="text-xs text-emerald-500">enabled</span>
                      )}
                    </td>
                    <td className="py-2 text-xs text-muted-foreground">
                      {new Date(t.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-2 text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => toggleDisabled.mutate(t)}
                        disabled={toggleDisabled.isPending}
                      >
                        {t.disabled ? "Re-enable" : "Disable"}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          if (
                            window.confirm(
                              `Delete tenant "${t.slug}"? This refuses if the tenant still owns rows.`,
                            )
                          ) {
                            remove.mutate(t);
                          }
                        }}
                        disabled={remove.isPending}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New tenant</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="tenant-slug">Slug</Label>
              <Input
                id="tenant-slug"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                placeholder="acme-corp"
                autoFocus
              />
              <div className="mt-1 text-xs text-muted-foreground">
                lowercase, dashes/digits allowed, must start with a letter
              </div>
            </div>
            <div>
              <Label htmlFor="tenant-name">Display name</Label>
              <Input
                id="tenant-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Acme Corp"
              />
            </div>
            {error && <div className="text-sm text-destructive">{error}</div>}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => create.mutate()}
              disabled={!slug.trim() || !name.trim() || create.isPending}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
