/**
 * M22.a: bulk-action confirmation dialog for the Alerts table.
 *
 * Two modes:
 *   - state transition: optional comment textarea (recorded on every
 *     state-history row).
 *   - assign: assignee picker (or "unassign").
 *
 * The dialog drives a single async run that walks the selected rows
 * and surfaces aggregated successes/failures inline instead of via
 * `window.alert`. Toast-style notifications land in M22.b.
 */
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";
import { ApiError } from "@/api/client";
import { usersApi } from "@/api/users";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import type { Alert, AlertState } from "@/types/api";

export type BulkMode = { kind: "state"; to: AlertState; label: string } | { kind: "assign" };

interface Props {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  mode: BulkMode | null;
  selection: Alert[];
}

interface RunResult {
  ok: number;
  failed: { id: string; reason: string }[];
}

export function AlertBulkDialog({ open, onOpenChange, mode, selection }: Props) {
  const qc = useQueryClient();
  const [comment, setComment] = useState("");
  const [assigneeId, setAssigneeId] = useState<string>("");
  const [result, setResult] = useState<RunResult | null>(null);

  useEffect(() => {
    if (open) {
      setComment("");
      setAssigneeId("");
      setResult(null);
    }
  }, [open, mode]);

  const usersQ = useQuery({
    queryKey: ["users-list"],
    queryFn: usersApi.list,
    enabled: open && mode?.kind === "assign",
  });

  const run = useMutation({
    mutationFn: async (): Promise<RunResult> => {
      if (!mode) return { ok: 0, failed: [] };
      let ok = 0;
      const failed: RunResult["failed"] = [];
      for (const a of selection) {
        try {
          if (mode.kind === "state") {
            await alertsApi.changeState(a.id, {
              to_state: mode.to,
              comment: comment.trim() || null,
            });
          } else {
            await alertsApi.assign(a.id, {
              assignee_id: assigneeId || null,
            });
          }
          ok += 1;
        } catch (err) {
          failed.push({
            id: a.id,
            reason: err instanceof ApiError ? err.detail : String(err),
          });
        }
      }
      return { ok, failed };
    },
    onSuccess: (r) => {
      setResult(r);
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["alert-stats"] });
      // Auto-close if everything succeeded; keep open on partial failure
      // so the operator can read which ids failed and why.
      if (r.failed.length === 0) {
        setTimeout(() => onOpenChange(false), 600);
      }
    },
  });

  if (!mode) return null;

  const title =
    mode.kind === "state"
      ? `${mode.label} (${selection.length})`
      : `Assign ${selection.length} alert${selection.length === 1 ? "" : "s"}`;

  const isTerminal = mode.kind === "state" && mode.to !== "investigating" && mode.to !== "new";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {mode.kind === "state"
              ? isTerminal
                ? "This is a terminal transition. The selected alerts can't be moved out again — add a short note explaining the call."
                : "Walks the selection one at a time. Disallowed rows are filtered out of the action upstream."
              : "Assigning bulk-applies to every selected alert. Pick a user, or choose Unassign to clear ownership."}
          </DialogDescription>
        </DialogHeader>

        {mode.kind === "state" && (
          <div className="space-y-1.5">
            <Label htmlFor="bulk-comment">
              Comment {isTerminal ? "(recommended)" : "(optional)"}
            </Label>
            <Textarea
              id="bulk-comment"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={3}
              placeholder={
                mode.to === "false_positive"
                  ? "e.g. tuned-out noisy installer, see ticket VIG-123"
                  : mode.to === "true_positive"
                    ? "e.g. confirmed by IR; remediation in progress"
                    : "Optional note for the audit trail."
              }
            />
          </div>
        )}

        {mode.kind === "assign" && (
          <div className="space-y-1.5">
            <Label htmlFor="bulk-assignee">Assignee</Label>
            <Select
              value={assigneeId || "__unassign__"}
              onValueChange={(v) => setAssigneeId(v === "__unassign__" ? "" : v)}
            >
              <SelectTrigger id="bulk-assignee">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__unassign__">(unassign)</SelectItem>
                {(usersQ.data ?? [])
                  .filter((u) => !u.disabled)
                  .map((u) => (
                    <SelectItem key={u.id} value={u.id}>
                      {u.email} · {u.role}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </div>
        )}

        {result && (
          <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
            <p className="font-medium">
              {result.ok} succeeded, {result.failed.length} failed
            </p>
            {result.failed.length > 0 && (
              <ul className="mt-1 max-h-32 space-y-0.5 overflow-auto text-muted-foreground">
                {result.failed.slice(0, 6).map((f) => (
                  <li key={f.id}>
                    <span className="font-mono">{f.id.slice(0, 8)}</span> — {f.reason}
                  </li>
                ))}
                {result.failed.length > 6 && (
                  <li className="text-muted-foreground/70">…and {result.failed.length - 6} more</li>
                )}
              </ul>
            )}
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={run.isPending}>
            {result ? "Close" : "Cancel"}
          </Button>
          {!result && (
            <Button
              onClick={() => run.mutate()}
              disabled={run.isPending || selection.length === 0}
              variant={isTerminal ? "destructive" : "default"}
            >
              {run.isPending ? "Running…" : `Apply to ${selection.length}`}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
