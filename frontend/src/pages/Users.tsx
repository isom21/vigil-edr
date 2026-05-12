/**
 * Users CRUD (admin-only).
 *
 * Replaces the M7 placeholder. List view + invite modal + per-row
 * drawer mirroring AlertDetailPanel's shape. Editing role / disabled /
 * password and assigning host groups all live in the drawer; delete
 * lives there too behind the shared ConfirmDestructive component.
 *
 * The backend's "can't disable / demote / delete the last enabled
 * admin" guard (api/users.py) bubbles up as a 400 — we surface the
 * detail inline rather than swallowing it.
 */
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, UserPlus } from "lucide-react";
import { ApiError } from "@/api/client";
import { hostGroupsApi } from "@/api/hostGroups";
import { usersApi, type UserUpdateBody } from "@/api/users";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { DataTable } from "@/components/data-table";
import type { ColumnDef } from "@/components/data-table";
import { DetailDrawer } from "@/components/DetailDrawer";
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
import { useColumnFilters } from "@/lib/table-filters";
import { useTableQuery } from "@/hooks/useTableQuery";
import type { User, UserRole } from "@/types/api";

const ROLES: UserRole[] = ["admin", "analyst", "viewer"];

export function Users() {
  const qc = useQueryClient();
  const { user: me } = useAuth();
  const { state, setSort, setOffset, setLimit, setHiddenCols } = useTableQuery({ limit: 50 });
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();

  const list = useQuery({
    queryKey: ["users"],
    queryFn: () => usersApi.list(),
  });

  const [createOpen, setCreateOpen] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const openUser = list.data?.find((u) => u.id === openId) ?? null;

  const columns: ColumnDef<User>[] = useMemo(
    () => [
      {
        id: "email",
        header: "Email",
        sortable: true,
        filterValue: (u) => u.email,
        cell: (u) => (
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">{u.email}</span>
            {u.id === me?.id && (
              <span className="rounded-sm bg-secondary px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                you
              </span>
            )}
          </div>
        ),
      },
      {
        id: "role",
        header: "Role",
        sortable: true,
        filterValue: (u) => u.role,
        cell: (u) => <RoleBadge role={u.role} />,
      },
      {
        id: "disabled",
        header: "Status",
        filterValue: (u) => (u.disabled ? "disabled" : "enabled"),
        cell: (u) =>
          u.disabled ? (
            <span className="text-xs text-muted-foreground">disabled</span>
          ) : (
            <span className="text-xs text-emerald-500">enabled</span>
          ),
      },
      {
        id: "last_login_at",
        header: "Last login",
        sortable: true,
        filterValue: (u) => u.last_login_at ?? "",
        cell: (u) => (
          <span className="text-xs tabular-nums text-muted-foreground">
            {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "—"}
          </span>
        ),
      },
      {
        id: "created_at",
        header: "Created",
        sortable: true,
        filterValue: (u) => u.created_at,
        cell: (u) => (
          <span className="text-xs tabular-nums text-muted-foreground">
            {new Date(u.created_at).toLocaleString()}
          </span>
        ),
      },
    ],
    [me?.id],
  );

  return (
    <>
      <PageHeader
        title="Users"
        description={`${list.data?.length ?? 0} users · admins manage role + host-group scope here.`}
        actions={
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <UserPlus className="h-3.5 w-3.5" aria-hidden="true" />
            Invite user
          </Button>
        }
      />
      <div className="space-y-4 px-8 py-6">
        <DataTable<User>
          tableId="users"
          columns={columns}
          rows={list.data}
          total={list.data?.length ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No users yet."
          getRowId={(u) => u.id}
          onRowClick={(u) => setOpenId(u.id)}
          sort={state.sort}
          onSortChange={setSort}
          offset={state.offset}
          limit={state.limit}
          onOffsetChange={setOffset}
          onLimitChange={setLimit}
          hiddenCols={state.hiddenCols}
          onHiddenColsChange={setHiddenCols}
          columnFilters={columnFilters}
          onColumnFiltersChange={setColumnFilters}
          savedFiltersTableId="users"
        />
      </div>
      {createOpen && (
        <CreateUserDialog
          onClose={() => setCreateOpen(false)}
          onCreated={() => {
            setCreateOpen(false);
            qc.invalidateQueries({ queryKey: ["users"] });
          }}
        />
      )}
      <DetailDrawer
        open={!!openUser}
        onOpenChange={(v) => !v && setOpenId(null)}
        title={openUser?.email ?? ""}
        description={openUser ? `User ${openUser.id.slice(0, 8)}…` : ""}
      >
        {openUser && (
          <UserDrawerContent
            user={openUser}
            isSelf={openUser.id === me?.id}
            onClose={() => setOpenId(null)}
          />
        )}
      </DetailDrawer>
    </>
  );
}

// ---------- Create user modal ----------

function CreateUserDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("analyst");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => usersApi.create({ email, password, role }),
    onSuccess: onCreated,
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Invite user</DialogTitle>
        </DialogHeader>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            create.mutate();
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="invite-email">Email</Label>
            <Input
              id="invite-email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@example.com"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="invite-password">Initial password</Label>
            <Input
              id="invite-password"
              type="password"
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="≥ 12 characters"
            />
            <p className="text-xs text-muted-foreground">
              The user signs in with this and changes it on first login. No email link —
              single-tenant deployments don&apos;t have SSO yet.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="invite-role">Role</Label>
            <Select
              id="invite-role"
              value={role}
              onChange={(e) => setRole(e.target.value as UserRole)}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </Select>
          </div>
          {error && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={create.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "Creating…" : "Create user"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------- Drawer body ----------

function UserDrawerContent({
  user,
  isSelf,
  onClose,
}: {
  user: User;
  isSelf: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [role, setRole] = useState<UserRole>(user.role);
  const [disabled, setDisabled] = useState(user.disabled);
  const [newPassword, setNewPassword] = useState("");
  const [savedError, setSavedError] = useState<string | null>(null);
  const [savedNotice, setSavedNotice] = useState<string | null>(null);

  // Reset local state when the drawer flips to another user.
  useEffect(() => {
    setRole(user.role);
    setDisabled(user.disabled);
    setNewPassword("");
    setSavedError(null);
    setSavedNotice(null);
  }, [user.id, user.role, user.disabled]);

  const groupsQ = useQuery({
    queryKey: ["user-groups", user.id],
    queryFn: () => usersApi.getGroups(user.id),
  });
  const allGroupsQ = useQuery({
    queryKey: ["host-groups", { limit: 200 }],
    queryFn: () => hostGroupsApi.list({ limit: 200 }),
  });
  const [selectedGroups, setSelectedGroups] = useState<Set<string>>(new Set());
  useEffect(() => {
    if (groupsQ.data) setSelectedGroups(new Set(groupsQ.data.host_group_ids));
  }, [groupsQ.data]);

  const save = useMutation({
    mutationFn: async () => {
      const body: UserUpdateBody = {};
      if (role !== user.role) body.role = role;
      if (disabled !== user.disabled) body.disabled = disabled;
      if (newPassword) body.password = newPassword;
      if (Object.keys(body).length === 0) return user;
      return usersApi.update(user.id, body);
    },
    onSuccess: () => {
      setSavedError(null);
      setSavedNotice("Saved.");
      setNewPassword("");
      qc.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (err) => setSavedError(err instanceof ApiError ? err.detail : String(err)),
  });

  const saveGroups = useMutation({
    mutationFn: () =>
      usersApi.replaceGroups(user.id, { host_group_ids: Array.from(selectedGroups) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-groups", user.id] });
    },
    onError: (err) => setSavedError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: () => usersApi.remove(user.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      onClose();
    },
    onError: (err) => setSavedError(err instanceof ApiError ? err.detail : String(err)),
  });

  const toggleGroup = (gid: string) => {
    setSelectedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(gid)) next.delete(gid);
      else next.add(gid);
      return next;
    });
  };

  const groupsDirty = useMemo(() => {
    const current = new Set(groupsQ.data?.host_group_ids ?? []);
    if (current.size !== selectedGroups.size) return true;
    for (const id of current) if (!selectedGroups.has(id)) return true;
    return false;
  }, [groupsQ.data, selectedGroups]);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Account</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Status</Label>
              <Select
                value={disabled ? "disabled" : "enabled"}
                onChange={(e) => setDisabled(e.target.value === "disabled")}
              >
                <option value="enabled">enabled</option>
                <option value="disabled">disabled</option>
              </Select>
            </div>
          </div>
          {isSelf && (
            <p className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-500">
              You&apos;re editing your own account. Demoting yourself or disabling the last enabled
              admin is rejected by the backend.
            </p>
          )}
          <div className="space-y-2">
            <Label htmlFor="reset-password">Reset password</Label>
            <Input
              id="reset-password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Leave blank to keep current"
              minLength={newPassword ? 12 : 0}
            />
          </div>
          {savedError && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {savedError}
            </div>
          )}
          {savedNotice && !savedError && (
            <div className="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-500">
              {savedNotice}
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={
                save.isPending || (role === user.role && disabled === user.disabled && !newPassword)
              }
              onClick={() => save.mutate()}
            >
              {save.isPending ? "Saving…" : "Save changes"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Host group access</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {allGroupsQ.isLoading || groupsQ.isLoading ? (
            <p className="text-xs text-muted-foreground">Loading…</p>
          ) : (allGroupsQ.data?.items.length ?? 0) === 0 ? (
            <p className="text-xs text-muted-foreground">
              No host groups defined yet — non-admins see no hosts until a group is created.
            </p>
          ) : (
            <ul className="space-y-1">
              {allGroupsQ.data?.items.map((g) => (
                <li key={g.id} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id={`group-${g.id}`}
                    checked={selectedGroups.has(g.id)}
                    onChange={() => toggleGroup(g.id)}
                  />
                  <label htmlFor={`group-${g.id}`} className="cursor-pointer text-sm">
                    {g.name}
                    <span className="ml-2 text-xs text-muted-foreground">
                      {g.host_count} host{g.host_count === 1 ? "" : "s"}
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          {user.role === "admin" && (
            <p className="text-xs text-muted-foreground">
              Admins are pass-through and see every host regardless of group membership.
            </p>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <Button
              size="sm"
              variant="outline"
              disabled={!groupsDirty || saveGroups.isPending}
              onClick={() => saveGroups.mutate()}
            >
              {saveGroups.isPending ? "Saving…" : "Save groups"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base text-destructive">Danger zone</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">
            Delete this user. Their audit-log rows are preserved (the audit log is append-only). The
            backend refuses if this would leave zero enabled admins.
          </p>
          <ConfirmDestructive
            title="Delete user?"
            description={
              <>
                <span className="font-mono">{user.email}</span> will be removed. Audit history
                stays.
              </>
            }
            confirmLabel="Yes, delete"
            onConfirm={() => remove.mutate()}
            pending={remove.isPending}
            trigger={
              <Button size="sm" variant="destructive">
                Delete
              </Button>
            }
          />
        </CardContent>
      </Card>
    </div>
  );
}

// ---------- Helpers ----------

function RoleBadge({ role }: { role: UserRole }) {
  const cls = {
    admin: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
    analyst: "bg-sev-high/15 text-sev-high border-sev-high/30",
    viewer: "bg-secondary/50 text-muted-foreground border-border",
  }[role];
  return (
    <span
      className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider ${cls}`}
    >
      {role}
    </span>
  );
}

// silence unused import warning if Plus is later replaced
void Plus;
