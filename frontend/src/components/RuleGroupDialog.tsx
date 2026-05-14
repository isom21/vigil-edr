/**
 * M20.g: create / edit a rule group.
 *
 * Groups belong to one kind (yara/sigma/ioc) and carry a `max_action`
 * ceiling. The kind is locked at create time (mirrors backend FK
 * validation) and not editable afterwards.
 */
import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ApiError } from "@/api/client";
import { ruleGroupsApi } from "@/api/ruleGroups";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import type { RuleAction, RuleGroup, RuleKind } from "@/types/api";

const ACTIONS: RuleAction[] = ["alert", "block", "quarantine"];

interface Props {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  /** create mode: pass `kind`. edit mode: pass `group`. */
  kind?: RuleKind;
  group?: RuleGroup;
}

export function RuleGroupDialog({ open, onOpenChange, kind, group }: Props) {
  const qc = useQueryClient();
  const editing = !!group;

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [maxAction, setMaxAction] = useState<RuleAction>("alert");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (group) {
      setName(group.name);
      setDescription(group.description ?? "");
      setMaxAction(group.max_action);
    } else if (open) {
      setName("");
      setDescription("");
      setMaxAction("alert");
    }
    setError(null);
  }, [group, open]);

  const save = useMutation({
    mutationFn: async () => {
      if (editing) {
        return ruleGroupsApi.update(group!.id, {
          name,
          description: description || null,
          max_action: maxAction,
        });
      }
      return ruleGroupsApi.create({
        kind: kind!,
        name,
        description: description || null,
        max_action: maxAction,
      });
    },
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["rule-groups"] });
      qc.invalidateQueries({ queryKey: ["rules"] });
      onOpenChange(false);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const effectiveKind = group?.kind ?? kind ?? "yara";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>
            {editing ? `Edit group · ${group!.name}` : `New ${effectiveKind.toUpperCase()} group`}
          </DialogTitle>
          <DialogDescription>
            Groups bucket rules of one kind under a shared <code>max_action</code> ceiling. Any rule
            with a stronger action is clamped down at fire time.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="rg-name">Name</Label>
            <Input
              id="rg-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. credential-access"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="rg-desc">Description (optional)</Label>
            <Textarea
              id="rg-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              placeholder="Short note on what this group covers."
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="rg-action">Max action (ceiling)</Label>
            <Select value={maxAction} onValueChange={(v) => setMaxAction(v as RuleAction)}>
              <SelectTrigger id="rg-action">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ACTIONS.map((a) => (
                  <SelectItem key={a} value={a}>
                    {a}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Rules in this group fire with at most this action — e.g. <code>alert</code> clamps
              every group rule to alert-only, regardless of its own setting.
            </p>
          </div>

          {error && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => save.mutate()} disabled={!name.trim() || save.isPending}>
            {save.isPending ? "Saving…" : editing ? "Save" : "Create group"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
