/**
 * Sequence / behavioral rules (Phase 2 #2.3).
 *
 * Operators author multi-step YAML rules; the sequence_detector worker
 * advances per-host state and emits an alert when the sequence
 * completes. The page surfaces hit counters + last-hit timestamp so
 * tuning is observable, with a side-by-side edit panel for the YAML.
 *
 * Analysts + viewers can read; admin role is required to mutate.
 */
import { FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Save, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { sequenceRulesApi } from "@/api/sequence_rules";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/useAuth";
import type { SequenceRule, Severity } from "@/types/api";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

const STARTER_YAML = `trigger:
  event_kind: process_started
  where: executable_basename == "rundll32.exe"
followed_by:
  within: 5s
  event_kind: network_connection
  where: dst_port == 443
then:
  emit_alert:
    severity: high
    message: "rundll32 network connect"
`;

export function SequenceRules() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const qc = useQueryClient();

  const list = useQuery({
    queryKey: ["sequence-rules"],
    queryFn: () => sequenceRulesApi.list({ limit: 200 }),
    refetchInterval: 30_000,
  });

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selected =
    selectedId != null ? (list.data?.items.find((r) => r.id === selectedId) ?? null) : null;

  const refresh = () => qc.invalidateQueries({ queryKey: ["sequence-rules"] });

  const create = useMutation({
    mutationFn: sequenceRulesApi.create,
    onSuccess: (r) => {
      refresh();
      setCreating(false);
      setSelectedId(r.id);
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const update = useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: string;
      body: Parameters<typeof sequenceRulesApi.update>[1];
    }) => sequenceRulesApi.update(id, body),
    onSuccess: () => {
      refresh();
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: sequenceRulesApi.remove,
    onSuccess: () => {
      refresh();
      setSelectedId(null);
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  return (
    <>
      <PageHeader
        title="Sequence rules"
        description={
          <span>
            Multi-step behavioural detections. The detector keeps per-host state with a TTL and
            emits an alert when the full sequence lands inside the window. Admins author; analysts
            and viewers can read.
          </span>
        }
        actions={
          isAdmin && (
            <Button
              size="sm"
              onClick={() => {
                setCreating(true);
                setSelectedId(null);
              }}
            >
              <Plus className="mr-1 h-4 w-4" aria-hidden="true" /> New rule
            </Button>
          )
        }
      />
      <div className="grid gap-6 p-8 lg:grid-cols-[2fr_3fr]">
        <Card>
          <CardHeader>
            <CardTitle>Rules</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead className="text-right">Hits</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.isLoading && (
                  <TableRow>
                    <TableCell colSpan={4} className="text-muted-foreground">
                      Loading…
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} className="text-muted-foreground">
                      No sequence rules yet.
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.items.map((r) => (
                  <TableRow
                    key={r.id}
                    className={r.id === selectedId ? "bg-secondary/40" : "cursor-pointer"}
                    onClick={() => {
                      setSelectedId(r.id);
                      setCreating(false);
                    }}
                  >
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{r.name}</span>
                        {r.description && (
                          <span className="line-clamp-1 text-[11px] text-muted-foreground">
                            {r.description}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs uppercase">
                        {r.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right text-xs tabular-nums">{r.hit_count}</TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {r.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {creating && (
          <Editor
            mode="create"
            initial={null}
            error={error}
            pending={create.isPending}
            readOnly={!isAdmin}
            onSubmit={(body) => create.mutate(body)}
            onCancel={() => setCreating(false)}
          />
        )}
        {!creating && selected && (
          <Editor
            mode="edit"
            initial={selected}
            error={error}
            pending={update.isPending}
            readOnly={!isAdmin}
            onSubmit={(body) => update.mutate({ id: selected.id, body })}
            onDelete={isAdmin ? () => remove.mutate(selected.id) : undefined}
            onCancel={() => setSelectedId(null)}
          />
        )}
        {!creating && !selected && (
          <Card>
            <CardHeader>
              <CardTitle>{isAdmin ? "Select or create a rule" : "Select a rule"}</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              {isAdmin
                ? 'Pick a rule on the left to edit, or click "New rule" to author a fresh one.'
                : "Pick a rule on the left to inspect its YAML."}
            </CardContent>
          </Card>
        )}
      </div>
    </>
  );
}

interface EditorProps {
  mode: "create" | "edit";
  initial: SequenceRule | null;
  error: string | null;
  pending: boolean;
  readOnly: boolean;
  onSubmit: (body: {
    name: string;
    description: string | null;
    yaml_body: string;
    window_s: number;
    enabled: boolean;
    severity: Severity;
    mitre_techniques: string[] | null;
  }) => void;
  onDelete?: () => void;
  onCancel: () => void;
}

function Editor({
  mode,
  initial,
  error,
  pending,
  readOnly,
  onSubmit,
  onDelete,
  onCancel,
}: EditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [yamlBody, setYamlBody] = useState(initial?.yaml_body ?? STARTER_YAML);
  const [windowS, setWindowS] = useState(initial?.window_s ?? 60);
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [severity, setSeverity] = useState<Severity>(initial?.severity ?? "medium");
  const [mitreInput, setMitreInput] = useState((initial?.mitre_techniques ?? []).join(", "));

  // The list panel hands us a fresh `initial` whenever the selection
  // changes; sync local state once per selection so the user's edits
  // aren't clobbered when the parent's refetch fires. Keying on `id`
  // is the load-bearing dependency — re-syncing on every `initial`
  // change would clobber edits on the next list refetch.
  const initialId = initial?.id;
  useEffect(() => {
    if (initial) {
      setName(initial.name);
      setDescription(initial.description ?? "");
      setYamlBody(initial.yaml_body);
      setWindowS(initial.window_s);
      setEnabled(initial.enabled);
      setSeverity(initial.severity);
      setMitreInput((initial.mitre_techniques ?? []).join(", "));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialId]);

  const handle = (e: FormEvent) => {
    e.preventDefault();
    const techniques = mitreInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    onSubmit({
      name: name.trim(),
      description: description.trim() || null,
      yaml_body: yamlBody,
      window_s: Math.max(1, Math.round(windowS)),
      enabled,
      severity,
      mitre_techniques: techniques.length > 0 ? techniques : null,
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{mode === "create" ? "New sequence rule" : `Edit: ${initial?.name}`}</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handle} className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="seq-name">Name</Label>
            <Input
              id="seq-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              disabled={readOnly}
              maxLength={255}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="seq-desc">Description</Label>
            <Input
              id="seq-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={readOnly}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="seq-window">Window (s)</Label>
              <Input
                id="seq-window"
                type="number"
                min={1}
                max={3600}
                value={windowS}
                onChange={(e) => setWindowS(Number(e.target.value))}
                disabled={readOnly}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="seq-severity">Severity</Label>
              <Select
                id="seq-severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
                disabled={readOnly}
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="seq-mitre">
              MITRE ATT&CK techniques{" "}
              <span className="text-xs text-muted-foreground">(comma-separated)</span>
            </Label>
            <Input
              id="seq-mitre"
              value={mitreInput}
              onChange={(e) => setMitreInput(e.target.value)}
              placeholder="T1055, T1059.001"
              disabled={readOnly}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="seq-yaml">YAML body</Label>
            <Textarea
              id="seq-yaml"
              value={yamlBody}
              onChange={(e) => setYamlBody(e.target.value)}
              rows={18}
              className="font-mono text-xs"
              disabled={readOnly}
              required
            />
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="seq-enabled"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              disabled={readOnly}
            />
            <Label htmlFor="seq-enabled" className="text-sm">
              Enabled
            </Label>
          </div>
          {error && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
          {!readOnly && (
            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" disabled={pending}>
                <Save className="mr-1 h-4 w-4" aria-hidden="true" />
                {mode === "create" ? "Create rule" : "Save changes"}
              </Button>
              <Button type="button" variant="ghost" onClick={onCancel}>
                Cancel
              </Button>
              {mode === "edit" && onDelete && (
                <ConfirmDestructive
                  title="Delete sequence rule?"
                  description={
                    <>
                      Removes the rule <span className="font-mono">{initial?.name}</span>.
                      Historical alerts that fired under it stay visible. This cannot be undone.
                    </>
                  }
                  confirmLabel="Delete rule"
                  onConfirm={onDelete}
                  trigger={
                    <Button type="button" variant="ghost" className="ml-auto text-destructive">
                      <Trash2 className="mr-1 h-4 w-4" aria-hidden="true" /> Delete
                    </Button>
                  }
                />
              )}
            </div>
          )}
        </form>
      </CardContent>
    </Card>
  );
}
