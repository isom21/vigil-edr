import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Plus } from "lucide-react";
import { scimTokensApi } from "@/api/scim_tokens";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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

/**
 * Phase 3 #3.8 — SCIM bearer token management.
 *
 * Each token is the credential a single IdP integration (Okta tenant /
 * Azure AD app / Google Workspace domain) uses to call our
 * /scim/v2/Users endpoints. The raw token is shown ONCE at creation
 * inside a copy-once banner; we keep only a sha256 hash, so the
 * operator either copies it now or rotates.
 */
export function ScimTokens() {
  const qc = useQueryClient();
  const tokens = useQuery({
    queryKey: ["scim-tokens"],
    queryFn: () => scimTokensApi.list(),
  });

  const [label, setLabel] = useState("");
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => scimTokensApi.create({ label }),
    onSuccess: (data) => {
      setCreated(data.token);
      setLabel("");
      qc.invalidateQueries({ queryKey: ["scim-tokens"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const disable = useMutation({
    mutationFn: (id: string) => scimTokensApi.disable(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scim-tokens"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => scimTokensApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scim-tokens"] }),
  });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setCreated(null);
    if (!label.trim()) {
      setError("label is required");
      return;
    }
    create.mutate();
  };

  return (
    <>
      <PageHeader
        title="SCIM tokens"
        description="Bearer tokens used by IdPs (Okta, Azure AD, Google Workspace) to provision users into Vigil via SCIM 2.0."
      />
      <div className="grid gap-4 p-8 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Issue token</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={onSubmit} className="space-y-3">
              <div className="space-y-2">
                <Label htmlFor="scim-label">Label</Label>
                <Input
                  id="scim-label"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="e.g. okta-prod"
                />
              </div>
              <Button type="submit" disabled={create.isPending}>
                <Plus className="h-4 w-4" /> Generate
              </Button>
              {error && (
                <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {error}
                </div>
              )}
              {created && (
                <div className="space-y-2 rounded-md bg-secondary p-3">
                  <div className="text-sm font-medium">Token (shown once)</div>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 break-all rounded bg-background p-2 text-xs">
                      {created}
                    </code>
                    <Button
                      type="button"
                      size="icon"
                      variant="outline"
                      onClick={() => navigator.clipboard.writeText(created)}
                      aria-label="Copy token"
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    The token isn&rsquo;t stored anywhere we can retrieve. Paste it into the
                    IdP&rsquo;s SCIM-config screen before navigating away.
                  </p>
                </div>
              )}
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Active tokens</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last used</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tokens.data?.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-muted-foreground">
                      No tokens.
                    </TableCell>
                  </TableRow>
                )}
                {tokens.data?.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-mono text-xs">{t.label}</TableCell>
                    <TableCell className="text-sm">
                      {new Date(t.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-sm">
                      {t.last_used_at ? new Date(t.last_used_at).toLocaleString() : "—"}
                    </TableCell>
                    <TableCell className="text-sm">{t.disabled ? "Disabled" : "Active"}</TableCell>
                    <TableCell className="text-right space-x-1">
                      {!t.disabled && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => disable.mutate(t.id)}
                          disabled={disable.isPending}
                        >
                          Disable
                        </Button>
                      )}
                      <ConfirmDestructive
                        title="Delete SCIM token?"
                        description={
                          <>
                            This permanently deletes <span className="font-mono">{t.label}</span>.
                            Any IdP still using it will start receiving 401s immediately.
                          </>
                        }
                        confirmLabel="Yes, delete"
                        onConfirm={() => remove.mutate(t.id)}
                        pending={remove.isPending}
                        trigger={
                          <Button size="sm" variant="ghost">
                            Delete
                          </Button>
                        }
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
