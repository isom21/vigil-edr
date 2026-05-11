import { FormEvent, useEffect, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";
import { rulesApi } from "@/api/rules";
import { ApiError } from "@/api/client";
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
  const [enabled, setEnabled] = useState(true);
  const [body, setBody] = useState("");
  const [iocs, setIocs] = useState<{ kind: IocKind; value: string }[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (existing.data) {
      const r = existing.data;
      setKind(r.kind);
      setName(r.name);
      setDescription(r.description ?? "");
      setSeverity(r.severity);
      setAction(r.action);
      setEnabled(r.enabled);
      setBody(r.body ?? "");
      setIocs(r.iocs.map((e) => ({ kind: e.kind, value: e.value })));
    }
  }, [existing.data]);

  const save = useMutation({
    mutationFn: async () => {
      const payload: RuleCreate = {
        kind,
        name,
        description: description || null,
        severity,
        action,
        enabled,
        body: kind === "ioc" ? null : body,
        iocs: kind === "ioc" ? iocs : undefined,
      };
      return isNew ? rulesApi.create(payload) : rulesApi.update(id!, payload);
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
            <Button variant="destructive" onClick={() => remove.mutate()}>
              <Trash2 className="h-4 w-4" /> Delete
            </Button>
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
                onChange={(e) => setKind(e.target.value as RuleKind)}
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
