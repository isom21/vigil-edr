/**
 * Playbook / runbook automation (Phase 3 #3.5).
 *
 * Operators author YAML response chains; the executor worker fires
 * them when an alert with matching triggers lands. This page is the
 * list + editor; the per-run timeline lives at `/playbooks/:id/runs`.
 *
 * Admins author + edit; analysts + viewers can read.
 */
import { FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { History, Plus, Save, Trash2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { playbooksApi } from "@/api/playbooks";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";
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
import type { Playbook } from "@/types/api";

type TriggerSeverity = "low" | "medium" | "high" | "critical";
const TRIGGER_SEVERITIES: TriggerSeverity[] = ["low", "medium", "high", "critical"];

// Starter YAML shown when the operator clicks "New playbook". Mirrors
// the LSASS dump example shipped in `backend/playbooks/`.
const STARTER_YAML = `steps:
  - isolate: {}
  - memory_yara:
      rule_id: lsass_credential_dump
  - notify_slack:
      channel_id: 00000000-0000-0000-0000-000000000001
`;

export function Playbooks() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const qc = useQueryClient();

  const list = useQuery({
    queryKey: ["playbooks"],
    queryFn: () => playbooksApi.list({ limit: 200 }),
    refetchInterval: 30_000,
  });

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selected =
    selectedId != null ? (list.data?.items.find((p) => p.id === selectedId) ?? null) : null;

  const refresh = () => qc.invalidateQueries({ queryKey: ["playbooks"] });

  const create = useMutation({
    mutationFn: playbooksApi.create,
    onSuccess: (p) => {
      refresh();
      setCreating(false);
      setSelectedId(p.id);
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof playbooksApi.update>[1] }) =>
      playbooksApi.update(id, body),
    onSuccess: () => {
      refresh();
      setError(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: playbooksApi.remove,
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
        title="Playbooks"
        description={
          <span>
            YAML-defined response chains. When an alert matches a playbook's trigger (rule,
            severity, or MITRE technique), the executor runs the playbook in addition to the rule's
            own action. Admins author; analysts and viewers read.
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
              <Plus className="mr-1 h-4 w-4" aria-hidden="true" /> New playbook
            </Button>
          )
        }
      />
      <div className="grid gap-6 p-8 lg:grid-cols-[2fr_3fr]">
        <Card>
          <CardHeader>
            <CardTitle>Playbooks</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-12" />
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
                      No playbooks yet.
                    </TableCell>
                  </TableRow>
                )}
                {list.data?.items.map((p) => (
                  <TableRow
                    key={p.id}
                    className={p.id === selectedId ? "bg-secondary/40" : "cursor-pointer"}
                    onClick={() => {
                      setSelectedId(p.id);
                      setCreating(false);
                    }}
                  >
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{p.name}</span>
                        {p.description && (
                          <span className="line-clamp-1 text-[11px] text-muted-foreground">
                            {p.description}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs">
                      {renderTriggerSummary(p) ?? (
                        <span className="text-muted-foreground">(dormant)</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {p.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <Link
                        to={`/playbooks/${p.id}/runs`}
                        onClick={(e) => e.stopPropagation()}
                        className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground"
                        aria-label={`Runs for ${p.name}`}
                      >
                        <History className="h-4 w-4" aria-hidden="true" />
                      </Link>
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
              <CardTitle>{isAdmin ? "Select or create a playbook" : "Select a playbook"}</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              {isAdmin
                ? 'Pick a playbook on the left to edit, or click "New playbook" to author a fresh one.'
                : "Pick a playbook on the left to inspect its YAML."}
            </CardContent>
          </Card>
        )}
      </div>
    </>
  );
}

function renderTriggerSummary(p: Playbook): string | null {
  const parts: string[] = [];
  if (p.trigger_rule_id) parts.push(`rule:${p.trigger_rule_id.slice(0, 8)}…`);
  if (p.trigger_severity) parts.push(`≥${p.trigger_severity}`);
  if (p.trigger_mitre_techniques && p.trigger_mitre_techniques.length > 0) {
    parts.push(p.trigger_mitre_techniques.join(", "));
  }
  return parts.length > 0 ? parts.join(" · ") : null;
}

interface EditorProps {
  mode: "create" | "edit";
  initial: Playbook | null;
  error: string | null;
  pending: boolean;
  readOnly: boolean;
  onSubmit: (body: {
    name: string;
    description: string | null;
    yaml_body: string;
    enabled: boolean;
    trigger_rule_id: string | null;
    trigger_severity: TriggerSeverity | null;
    trigger_mitre_techniques: string[] | null;
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
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [triggerRuleId, setTriggerRuleId] = useState(initial?.trigger_rule_id ?? "");
  const [triggerSeverity, setTriggerSeverity] = useState<TriggerSeverity | "">(
    initial?.trigger_severity ?? "",
  );
  const [mitreInput, setMitreInput] = useState(
    (initial?.trigger_mitre_techniques ?? []).join(", "),
  );

  const initialId = initial?.id;
  useEffect(() => {
    if (initial) {
      setName(initial.name);
      setDescription(initial.description ?? "");
      setYamlBody(initial.yaml_body);
      setEnabled(initial.enabled);
      setTriggerRuleId(initial.trigger_rule_id ?? "");
      setTriggerSeverity(initial.trigger_severity ?? "");
      setMitreInput((initial.trigger_mitre_techniques ?? []).join(", "));
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
      enabled,
      trigger_rule_id: triggerRuleId.trim() || null,
      trigger_severity: triggerSeverity || null,
      trigger_mitre_techniques: techniques.length > 0 ? techniques : null,
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-2">
          <span>{mode === "create" ? "New playbook" : `Edit: ${initial?.name}`}</span>
          {mode === "edit" && initial && (
            <Link
              to={`/playbooks/${initial.id}/runs`}
              className="inline-flex items-center gap-1 text-xs font-normal text-muted-foreground hover:text-foreground"
            >
              <History className="h-3 w-3" aria-hidden="true" /> Runs
            </Link>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handle} className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="pb-name">Name</Label>
            <Input
              id="pb-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              disabled={readOnly}
              maxLength={255}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="pb-desc">Description</Label>
            <Input
              id="pb-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={readOnly}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="pb-sev">Trigger severity (floor)</Label>
              <Select
                id="pb-sev"
                value={triggerSeverity}
                onChange={(e) => setTriggerSeverity(e.target.value as TriggerSeverity | "")}
                disabled={readOnly}
              >
                <option value="">(none)</option>
                {TRIGGER_SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="pb-rule">Trigger rule ID</Label>
              <Input
                id="pb-rule"
                value={triggerRuleId}
                onChange={(e) => setTriggerRuleId(e.target.value)}
                placeholder="(none)"
                disabled={readOnly}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="pb-mitre">
              Trigger MITRE techniques{" "}
              <span className="text-xs text-muted-foreground">(comma-separated)</span>
            </Label>
            <Input
              id="pb-mitre"
              value={mitreInput}
              onChange={(e) => setMitreInput(e.target.value)}
              placeholder="T1003.001, T1486"
              disabled={readOnly}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="pb-yaml">YAML body</Label>
            <Textarea
              id="pb-yaml"
              value={yamlBody}
              onChange={(e) => setYamlBody(e.target.value)}
              rows={18}
              className="font-mono text-xs"
              disabled={readOnly}
              required
              spellCheck={false}
            />
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="pb-enabled"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              disabled={readOnly}
            />
            <Label htmlFor="pb-enabled" className="text-sm">
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
                {mode === "create" ? "Create playbook" : "Save changes"}
              </Button>
              <Button type="button" variant="ghost" onClick={onCancel}>
                Cancel
              </Button>
              {mode === "edit" && onDelete && (
                <ConfirmDestructive
                  title="Delete playbook?"
                  description={
                    <>
                      Removes the playbook <span className="font-mono">{initial?.name}</span>.
                      Historical runs that fired under it stay visible. This cannot be undone.
                    </>
                  }
                  confirmLabel="Delete playbook"
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
