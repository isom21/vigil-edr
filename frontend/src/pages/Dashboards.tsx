/**
 * Dashboards directory (Phase 3 #3.4).
 *
 * Lists every dashboard the actor can see — own dashboards plus
 * anything shared — with quick actions to open, duplicate, and
 * delete. The "Create new" button drops the user into the editor on
 * a fresh row.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Copy, Plus, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { dashboardsApi } from "@/api/dashboards";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/useAuth";

export function Dashboards() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [error, setError] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["dashboards"],
    queryFn: () => dashboardsApi.list(),
  });

  const create = useMutation({
    mutationFn: () =>
      dashboardsApi.create({
        name: "New dashboard",
        widgets_json: [],
      }),
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ["dashboards"] });
      navigate(`/dashboards/${d.id}`);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const duplicate = useMutation({
    mutationFn: (id: string) => dashboardsApi.duplicate(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dashboards"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => dashboardsApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dashboards"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  return (
    <>
      <PageHeader
        title="Dashboards"
        description="Author and share dashboards across the team."
        actions={
          <Button size="sm" onClick={() => create.mutate()} disabled={create.isPending}>
            <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
            New dashboard
          </Button>
        }
      />
      <div className="p-8">
        {error && (
          <p className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {error}
          </p>
        )}
        <Card>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Shared</TableHead>
                  <TableHead>Default</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.isLoading && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-muted-foreground">
                      Loading…
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-muted-foreground">
                      No dashboards yet — start one with "New dashboard".
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.map((d) => {
                  const owned = d.owner_user_id === user?.id;
                  const canEdit = owned || user?.role === "admin";
                  return (
                    <TableRow key={d.id}>
                      <TableCell>
                        <Link to={`/dashboards/${d.id}`} className="font-medium hover:underline">
                          {d.name}
                        </Link>
                        {d.description && (
                          <div className="max-w-md truncate text-xs text-muted-foreground">
                            {d.description}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {owned ? "you" : d.owner_user_id.slice(0, 8)}
                      </TableCell>
                      <TableCell>
                        {d.shared ? (
                          <Badge variant="default" className="text-[10px]">
                            shared
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {d.is_default ? (
                          <Badge variant="outline" className="text-[10px]">
                            default
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                        {new Date(d.updated_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => duplicate.mutate(d.id)}
                            disabled={duplicate.isPending}
                            title="Duplicate"
                          >
                            <Copy className="h-4 w-4" aria-hidden="true" />
                          </Button>
                          {canEdit && (
                            <ConfirmDestructive
                              title="Delete dashboard?"
                              description={
                                <>
                                  This permanently removes{" "}
                                  <span className="font-mono">{d.name}</span>.
                                </>
                              }
                              confirmLabel="Delete"
                              onConfirm={() => remove.mutate(d.id)}
                              pending={remove.isPending}
                              trigger={
                                <Button size="sm" variant="ghost">
                                  <Trash2 className="h-4 w-4" aria-hidden="true" />
                                </Button>
                              }
                            />
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
