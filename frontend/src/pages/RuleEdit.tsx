import { FormEvent, useEffect, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";
import { rulesApi } from "@/api/rules";
import { ruleGroupsApi } from "@/api/ruleGroups";
import { ApiError } from "@/api/client";
import { RuleActionBadge } from "@/components/badges";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/PageHeader";
import { SigmaPanel } from "@/components/SigmaPanel";
import type { IocKind, RuleAction, RuleCreate, RuleKind, Severity } from "@/types/api";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
const ACTIONS: RuleAction[] = ["alert", "block", "quarantine"];
const IOC_KINDS: IocKind[] = ["hash_sha256", "hash_md5", "hash_sha1", "filename", "filepath"];
const ACTION_ORDER: Record<RuleAction, number> = { alert: 0, block: 1, quarantine: 2 };
// Backend sentinel for "unassign group" on PATCH — see api/rules.py.
const NULL_GROUP_SENTINEL = "00000000-0000-0000-0000-000000000000";

export function RuleEdit() {
  const { id } = useParams<{ id: string }>();
  const [search] = useSearchParams();
  const isNew = !id || id === "new";
  const navigate = useNavigate();
  const qc = useQueryClient();

  const existing = useQuery({
    queryKey: ["rule", id],
    queryFn: () => rulesApi.get(id!),
    enabled: !isNew,
  });

  const [kind, setKind] = useState<RuleKind>((search.get("kind") as RuleKind) || "yara");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [action, setAction] = useState<RuleAction>("alert");
  const [groupId, setGroupId] = useState<string | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [body, setBody] = useState("");
  const [iocs, setIocs] = useState<{ kind: IocKind; value: string }[]>([]);
  // Phase 1 #1.8: free-text comma-separated MITRE ATT&CK technique IDs.
  // We keep the raw input string in state so users can edit mid-list;
  // the backend normalises on save (trim/upper/dedupe).
  const [mitreInput, setMitreInput] = useState("");
  // Phase 2 #2.1: when an alert from this rule carries process.pid,
  // the manager auto-queues an in-memory YARA job against that pid.
  const [autoMemoryScan, setAutoMemoryScan] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Groups list scoped to the current kind — cross-kind assignment is
  // rejected by the backend, so we just hide those entries client-side.
  const groupsQ = useQuery({
    queryKey: ["rule-groups", kind],
    queryFn: () => ruleGroupsApi.list({ kind, limit: 100 }),
  });
  const groups = groupsQ.data?.items ?? [];
  const selectedGroup = groups.find((g) => g.id === groupId) ?? null;
  const ceiling = selectedGroup?.max_action ?? null;
  const clamped = ceiling != null && ACTION_ORDER[action] > ACTION_ORDER[ceiling] ? ceiling : null;

  useEffect(() => {
    if (existing.data) {
      const r = existing.data;
      setKind(r.kind);
      setName(r.name);
      setDescription(r.description ?? "");
      setSeverity(r.severity);
      setAction(r.action);
      setGroupId(r.group_id);
      setEnabled(r.enabled);
      setBody(r.body ?? "");
      setIocs(r.iocs.map((e) => ({ kind: e.kind, value: e.value })));
      setMitreInput((r.mitre_techniques ?? []).join(", "));
      setAutoMemoryScan(r.auto_memory_scan);
    }
  }, [existing.data]);

  const save = useMutation({
    mutationFn: async () => {
      const techniques = mitreInput
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const payload: RuleCreate = {
        kind,
        name,
        description: description || null,
        severity,
        action,
        enabled,
        body: kind === "ioc" ? null : body,
        iocs: kind === "ioc" ? iocs : undefined,
        // Always send the list (possibly empty) on update so clearing
        // the field wipes the column server-side. Backend normalises
        // empty/whitespace to NULL.
        mitre_techniques: techniques,
        auto_memory_scan: autoMemoryScan,
      };
      if (isNew) {
        // Create accepts a real UUID or null; sentinel only matters on PATCH.
        payload.group_id = groupId;
        return rulesApi.create(payload);
      }
      // Update: send sentinel when the user cleared the group so the
      // backend writes NULL (passing null would be treated as "no change").
      const updatePayload = {
        ...payload,
        group_id: groupId ?? NULL_GROUP_SENTINEL,
      };
      return rulesApi.update(id!, updatePayload);
    },
    onSuccess: (rule) => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      qc.invalidateQueries({ queryKey: ["rule", rule.id] });
      navigate(`/rules`);
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const remove = useMutation({
    mutationFn: () => rulesApi.remove(id!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      navigate("/rules");
    },
  });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    save.mutate();
  };

  return (
    <>
      <PageHeader
        title={isNew ? "New rule" : name || "Edit rule"}
        actions={
          !isNew && (
            <ConfirmDestructive
              title="Delete rule?"
              description={
                <>
                  <span className="font-mono">{name || id}</span> will be removed permanently.
                  Existing alerts it produced remain, but the rule won't fire again.
                </>
              }
              confirmLabel="Yes, delete"
              onConfirm={() => remove.mutate()}
              pending={remove.isPending}
              trigger={
                <Button variant="destructive">
                  <Trash2 className="h-4 w-4" /> Delete
                </Button>
              }
            />
          )
        }
      />
      <form onSubmit={onSubmit} className="grid gap-4 p-8">
        <Card>
          <CardHeader>
            <CardTitle>Metadata</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>Kind</Label>
              <Select
                value={kind}
                onChange={(e) => {
                  setKind(e.target.value as RuleKind);
                  // Groups are kind-scoped — selecting a yara rule into
                  // a sigma group is a 400 from the backend, so we drop
                  // the current selection whenever kind changes.
                  setGroupId(null);
                }}
                disabled={!isNew}
              >
                <option value="yara">YARA</option>
                <option value="sigma">Sigma</option>
                <option value="ioc">IOC</option>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="space-y-2 md:col-span-2">
              <Label>Description</Label>
              <Input value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
            <div className="space-y-2 md:col-span-2">
              <Label htmlFor="mitre-techniques">MITRE ATT&amp;CK techniques</Label>
              <Input
                id="mitre-techniques"
                value={mitreInput}
                onChange={(e) => setMitreInput(e.target.value)}
                placeholder="T1059.001, T1547.001"
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Comma-separated technique IDs (e.g. <span className="font-mono">T1059.001</span>).
                Copied onto every alert this rule fires so historical queries stay stable when this
                list changes later.
              </p>
            </div>
            <div className="space-y-2">
              <Label>Severity</Label>
              <Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Action</Label>
              <Select value={action} onChange={(e) => setAction(e.target.value as RuleAction)}>
                {ACTIONS.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-2 md:col-span-2">
              <Label>Group</Label>
              <Select value={groupId ?? ""} onChange={(e) => setGroupId(e.target.value || null)}>
                <option value="">(none — ungrouped)</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name} · max action: {g.max_action}
                  </option>
                ))}
              </Select>
              {clamped ? (
                <p className="text-xs text-muted-foreground">
                  Group ceiling clamps this rule's effective action to{" "}
                  <RuleActionBadge action={clamped} /> at fire time.
                </p>
              ) : selectedGroup ? (
                <p className="text-xs text-muted-foreground">
                  Group ceiling allows the configured action — fires as{" "}
                  <RuleActionBadge action={action} />.
                </p>
              ) : (
                <p className="text-xs text-muted-foreground">
                  No group selected — action runs unclamped.
                </p>
              )}
            </div>
            <div className="flex items-center gap-2 md:col-span-2">
              <input
                id="enabled"
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
                className="h-4 w-4"
              />
              <Label htmlFor="enabled">Enabled</Label>
            </div>
            <div className="space-y-1 md:col-span-2">
              <div className="flex items-center gap-2">
                <input
                  id="auto-memory-scan"
                  type="checkbox"
                  checked={autoMemoryScan}
                  onChange={(e) => setAutoMemoryScan(e.target.checked)}
                  className="h-4 w-4"
                />
                <Label htmlFor="auto-memory-scan">Auto memory YARA scan on alert</Label>
              </div>
              <p className="text-xs text-muted-foreground">
                When this rule fires on an event carrying{" "}
                <span className="font-mono">process.pid</span>, queue an in-memory YARA scan against
                that pid on the originating host. The match list lands as a Job artifact.
              </p>
            </div>
          </CardContent>
        </Card>

        {kind !== "ioc" ? (
          <>
            <Card>
              <CardHeader>
                <CardTitle>{kind === "yara" ? "YARA source" : "Sigma YAML"}</CardTitle>
              </CardHeader>
              <CardContent>
                <Textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  rows={20}
                  placeholder={
                    kind === "yara"
                      ? 'rule example_rule { strings: $a = "bad" condition: $a }'
                      : "title: Suspicious thing\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n  selection:\n    process.name|contains: 'bad'\n  condition: selection"
                  }
                />
              </CardContent>
            </Card>
            {kind === "sigma" && <SigmaPanel body={body} ruleId={id} isNew={isNew} />}
          </>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>IOC entries ({iocs.length})</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {iocs.map((entry, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Select
                    value={entry.kind}
                    onChange={(e) => {
                      const next = [...iocs];
                      next[i] = { ...entry, kind: e.target.value as IocKind };
                      setIocs(next);
                    }}
                    className="w-44"
                  >
                    {IOC_KINDS.map((k) => (
                      <option key={k} value={k}>
                        {k}
                      </option>
                    ))}
                  </Select>
                  <Input
                    value={entry.value}
                    onChange={(e) => {
                      const next = [...iocs];
                      next[i] = { ...entry, value: e.target.value };
                      setIocs(next);
                    }}
                    className="flex-1 font-mono"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => setIocs(iocs.filter((_, j) => j !== i))}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                onClick={() => setIocs([...iocs, { kind: "hash_sha256", value: "" }])}
              >
                Add entry
              </Button>
            </CardContent>
          </Card>
        )}

        {error && (
          <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={() => navigate("/rules")}>
            Cancel
          </Button>
          <Button type="submit" disabled={save.isPending}>
            {save.isPending ? "Saving..." : "Save"}
          </Button>
        </div>
      </form>
    </>
  );
}
