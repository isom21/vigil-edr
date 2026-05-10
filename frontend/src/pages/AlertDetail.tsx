import { useState } from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/PageHeader";
import { CommandDialog } from "@/components/CommandDialog";
import type { AlertState } from "@/types/api";

const NEXT_STATES: Record<AlertState, AlertState[]> = {
  new: ["investigating", "false_positive", "true_positive"],
  investigating: ["false_positive", "true_positive", "new"],
  false_positive: [],
  true_positive: [],
};

export function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["alert", id],
    queryFn: () => alertsApi.get(id!),
    enabled: !!id,
  });

  const transition = useMutation({
    mutationFn: (to: AlertState) =>
      alertsApi.changeState(id!, { to_state: to, comment: comment || null }),
    onSuccess: () => {
      setComment("");
      qc.invalidateQueries({ queryKey: ["alert", id] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  if (isLoading) return <div className="p-8 text-muted-foreground">loading...</div>;
  if (!data) return <div className="p-8">not found</div>;

  const possible = NEXT_STATES[data.state];

  return (
    <>
      <PageHeader title={data.summary} description={`Alert ${data.id}`} />
      <div className="grid gap-4 p-8 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Overview</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">State</span>
              <Badge>{data.state}</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Severity</span>
              <Badge variant="outline">{data.severity}</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Action taken</span>
              <span>{data.action_taken}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Host</span>
              <code className="text-xs">{data.host_id}</code>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Rule</span>
              <code className="text-xs">{data.rule_id}</code>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Opened</span>
              <span>{new Date(data.opened_at).toLocaleString()}</span>
            </div>
            {data.closed_at && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">Closed</span>
                <span>{new Date(data.closed_at).toLocaleString()}</span>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Response actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-sm text-muted-foreground">
              Queue a response action against this alert's host. Status lands on{" "}
              <a className="underline" href="/commands">/commands</a> once the agent confirms.
            </p>
            <div className="flex flex-wrap gap-2">
              <CommandDialog
                hostId={data.host_id}
                trigger={<Button variant="outline">Block process by path...</Button>}
                defaultKind="block_process"
              />
              <CommandDialog
                hostId={data.host_id}
                trigger={<Button variant="outline">Block file...</Button>}
                defaultKind="block_file"
              />
              <CommandDialog
                hostId={data.host_id}
                trigger={<Button variant="destructive">Kill PID...</Button>}
                defaultKind="kill_process"
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Triage</CardTitle>
          </CardHeader>
          <CardContent>
            {possible.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                Alert is in a terminal state — no further transitions.
              </p>
            ) : (
              <div className="space-y-3">
                <Textarea
                  placeholder="Optional comment..."
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  rows={3}
                />
                <div className="flex flex-wrap gap-2">
                  {possible.map((s) => (
                    <Button key={s} onClick={() => transition.mutate(s)} variant="outline">
                      Move to {s.replace("_", " ")}
                    </Button>
                  ))}
                </div>
                {error && (
                  <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                    {error}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>History</CardTitle>
          </CardHeader>
          <CardContent>
            {data.history.length === 0 ? (
              <p className="text-sm text-muted-foreground">No transitions yet.</p>
            ) : (
              <ul className="space-y-2 text-sm">
                {data.history.map((h) => (
                  <li key={h.id} className="rounded-md border p-3">
                    <div className="flex items-center justify-between">
                      <span>
                        <Badge variant="outline">{h.from_state ?? "—"}</Badge>{" "}
                        →{" "}
                        <Badge>{h.to_state}</Badge>
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {new Date(h.ts).toLocaleString()}
                      </span>
                    </div>
                    {h.comment && (
                      <div className="mt-1 text-muted-foreground">{h.comment}</div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
