import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { CommandDialog } from "@/components/CommandDialog";
import { AlertStateBadge, RuleActionBadge, SeverityBadge } from "@/components/badges";
import type { AlertDetail, AlertState } from "@/types/api";

const NEXT_STATES: Record<AlertState, AlertState[]> = {
  new: ["investigating", "false_positive", "true_positive"],
  investigating: ["false_positive", "true_positive", "new"],
  false_positive: [],
  true_positive: [],
};

interface Props {
  alert: AlertDetail;
}

export function AlertDetailPanel({ alert }: Props) {
  const qc = useQueryClient();
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  const transition = useMutation({
    mutationFn: (to: AlertState) =>
      alertsApi.changeState(alert.id, { to_state: to, comment: comment || null }),
    onSuccess: () => {
      setComment("");
      setError(null);
      qc.invalidateQueries({ queryKey: ["alert", alert.id] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["alert-stats"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const possible = NEXT_STATES[alert.state];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Overview</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <Row label="State" value={<AlertStateBadge state={alert.state} />} />
          <Row label="Severity" value={<SeverityBadge severity={alert.severity} />} />
          <Row label="Action taken" value={<RuleActionBadge action={alert.action_taken} />} />
          <Row label="Host" value={alert.host_hostname ?? alert.host_id.slice(0, 8) + "…"} />
          <Row label="Rule" value={alert.rule_name ?? alert.rule_id.slice(0, 8) + "…"} />
          <Row label="Opened" value={new Date(alert.opened_at).toLocaleString()} />
          {alert.closed_at && (
            <Row label="Closed" value={new Date(alert.closed_at).toLocaleString()} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Triage</CardTitle>
        </CardHeader>
        <CardContent>
          {possible.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Alert is in a terminal state — no further transitions.
            </p>
          ) : (
            <div className="space-y-3">
              <Textarea
                placeholder="Optional comment…"
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                rows={3}
              />
              <div className="flex flex-wrap gap-2">
                {possible.map((s) => (
                  <Button key={s} onClick={() => transition.mutate(s)} variant="outline" size="sm">
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

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Response actions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <p className="text-xs text-muted-foreground">
            Queue an action against this alert's host. Status appears on{" "}
            <a className="underline" href="/commands">
              /commands
            </a>{" "}
            once the agent confirms.
          </p>
          <div className="flex flex-wrap gap-2">
            <CommandDialog
              hostId={alert.host_id}
              trigger={
                <Button variant="outline" size="sm">
                  Block process by path…
                </Button>
              }
              defaultKind="block_process"
            />
            <CommandDialog
              hostId={alert.host_id}
              trigger={
                <Button variant="outline" size="sm">
                  Block file…
                </Button>
              }
              defaultKind="block_file"
            />
            <CommandDialog
              hostId={alert.host_id}
              trigger={
                <Button variant="destructive" size="sm">
                  Kill PID…
                </Button>
              }
              defaultKind="kill_process"
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">History</CardTitle>
        </CardHeader>
        <CardContent>
          {alert.history.length === 0 ? (
            <p className="text-sm text-muted-foreground">No transitions yet.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {alert.history.map((h) => (
                <li key={h.id} className="rounded-md border p-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className="flex items-center gap-2">
                      {h.from_state ? (
                        <AlertStateBadge state={h.from_state} />
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                      <span className="text-muted-foreground">→</span>
                      <AlertStateBadge state={h.to_state} />
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {new Date(h.ts).toLocaleString()}
                    </span>
                  </div>
                  {h.comment && <div className="mt-1 text-muted-foreground">{h.comment}</div>}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-foreground">{value}</span>
    </div>
  );
}
