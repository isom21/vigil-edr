/**
 * Saved hunts directory (Phase 2 #2.11).
 *
 * Lists the hunts the actor can see (own ones for analysts; all of
 * them for admins) with last-run / schedule indicators and per-row
 * actions: open in the workbench, run manually, delete.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Calendar, Play, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { huntApi } from "@/api/hunt";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { useState } from "react";

export function SavedHunts() {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["saved-hunts"],
    queryFn: () => huntApi.listSaved({ limit: 200 }),
    refetchInterval: 30_000,
  });

  const runNow = useMutation({
    mutationFn: (id: string) => huntApi.runSaved(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saved-hunts"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => huntApi.removeSaved(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saved-hunts"] }),
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  return (
    <>
      <PageHeader
        title="Saved hunts"
        description="Run, edit, or delete previously-saved hunt queries. Admin-managed hunts may run on a cron schedule and emit alerts on hit."
      />
      <div className="p-8">
        {error && (
          <p className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {error}
          </p>
        )}
        <Card>
          <CardHeader>
            <CardTitle>Hunts</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Language</TableHead>
                  <TableHead>Schedule</TableHead>
                  <TableHead>Alert</TableHead>
                  <TableHead>Last run</TableHead>
                  <TableHead className="text-right">Hits</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.isLoading && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-muted-foreground">
                      Loading…
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-muted-foreground">
                      No saved hunts yet. Author one in the workbench.
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.items.map((h) => (
                  <TableRow key={h.id}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{h.name}</span>
                        {h.description && (
                          <span className="max-w-md truncate text-xs text-muted-foreground">
                            {h.description}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px] uppercase">
                        {h.query_language}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums text-muted-foreground">
                      {h.schedule_cron ? (
                        <span className="inline-flex items-center gap-1">
                          <Calendar className="h-3 w-3" aria-hidden="true" />
                          <span className="font-mono">{h.schedule_cron}</span>
                        </span>
                      ) : (
                        "—"
                      )}
                    </TableCell>
                    <TableCell>
                      {h.alert_on_hit ? (
                        <Badge variant="default" className="text-[10px]">
                          {h.severity ?? "medium"}
                        </Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                      {h.last_run_at ? new Date(h.last_run_at).toLocaleString() : "—"}
                    </TableCell>
                    <TableCell className="text-right text-xs tabular-nums">
                      {h.last_run_hit_count ?? "—"}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => runNow.mutate(h.id)}
                          disabled={runNow.isPending}
                          title="Run now"
                        >
                          <Play className="h-4 w-4" aria-hidden="true" />
                        </Button>
                        <ConfirmDestructive
                          title="Delete saved hunt?"
                          description={
                            <>
                              This permanently removes the hunt{" "}
                              <span className="font-mono">{h.name}</span> and its run history.
                            </>
                          }
                          confirmLabel="Delete hunt"
                          onConfirm={() => remove.mutate(h.id)}
                          pending={remove.isPending}
                          trigger={
                            <Button size="sm" variant="ghost">
                              <Trash2 className="h-4 w-4" aria-hidden="true" />
                            </Button>
                          }
                        />
                      </div>
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
