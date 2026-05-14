/**
 * Hunt workbench (Phase 2 #2.11).
 *
 * Operator-driven OpenSearch query editor over the telemetry-* indices.
 * Authors pick a language (Lucene / KQL / Sigma YAML), type the query
 * into a styled textarea, and run it ad-hoc. Each ad-hoc run is
 * audited. Authors can save the working query for later or export the
 * current result set to CSV.
 *
 * The textarea here is deliberately not Monaco — the project doesn't
 * yet ship `@monaco-editor/react`, and a plain textarea keeps the page
 * bundle small + accessible by default. A future enhancement can swap
 * in a richer editor without touching the surrounding workflow.
 */
import { FormEvent, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Download, Loader2, Play, Save, Sparkles } from "lucide-react";

import { aiApi } from "@/api/ai";
import { ApiError } from "@/api/client";
import { huntApi } from "@/api/hunt";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
import type {
  HuntQueryLanguage,
  HuntResultHit,
  HuntRunResult,
  HuntSeverity,
  SavedHuntCreate,
} from "@/types/api";

const LANGUAGE_LABEL: Record<HuntQueryLanguage, string> = {
  lucene: "Lucene",
  kql: "KQL (Lucene-compatible)",
  sigma: "Sigma YAML",
};

const LOOKBACK_OPTIONS: { value: number; label: string }[] = [
  { value: 1, label: "Last 1 h" },
  { value: 24, label: "Last 24 h" },
  { value: 72, label: "Last 3 d" },
  { value: 168, label: "Last 7 d" },
  { value: 720, label: "Last 30 d" },
];

function hitsToCsv(hits: HuntResultHit[]): string {
  const header = ["timestamp", "host_id", "event_id", "source_json"];
  const rows = hits.map((h) => [
    h.timestamp ?? "",
    h.host_id ?? "",
    h.event_id ?? "",
    JSON.stringify(h.source).replace(/"/g, '""'),
  ]);
  const lines = [header.join(","), ...rows.map((r) => r.map((c) => `"${c}"`).join(","))];
  return lines.join("\n");
}

function downloadCsv(filename: string, body: string): void {
  const blob = new Blob([body], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function Hunt() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [query, setQuery] = useState("");
  const [language, setLanguage] = useState<HuntQueryLanguage>("lucene");
  const [lookbackHours, setLookbackHours] = useState<number>(24);
  const [size, setSize] = useState<number>(100);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<HuntRunResult | null>(null);
  const [showSave, setShowSave] = useState(false);
  // Phase 4 #4.1 — Translate-from-English. Lives next to the query
  // body so the analyst can describe what they want and pipe the
  // model's translation into the same textarea the manual editor
  // uses.
  const [nlPrompt, setNlPrompt] = useState("");
  const [nlError, setNlError] = useState<string | null>(null);
  const nlTranslate = useMutation({
    mutationFn: aiApi.nlToQuery,
    onSuccess: (data) => {
      setQuery(data.query);
      setNlError(null);
    },
    onError: (err) => {
      setNlError(err instanceof ApiError ? err.detail : String(err));
    },
  });

  const runAdhoc = useMutation({
    mutationFn: huntApi.runAdhoc,
    onSuccess: (data) => {
      setResult(data);
      setError(null);
    },
    onError: (err) => {
      setResult(null);
      setError(err instanceof ApiError ? err.detail : String(err));
    },
  });

  function onRun(e: FormEvent): void {
    e.preventDefault();
    if (!query.trim()) {
      setError("query is empty");
      return;
    }
    runAdhoc.mutate({
      query,
      language,
      lookback_hours: lookbackHours,
      size,
    });
  }

  return (
    <>
      <PageHeader
        title="Hunt workbench"
        description="Query telemetry-* indices on demand. Ad-hoc runs are audited; save a query to re-run it later or schedule it."
      />
      <div className="grid gap-6 p-8 lg:grid-cols-[1fr_2fr]">
        <Card>
          <CardHeader>
            <CardTitle>Query</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={onRun} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label htmlFor="hunt-language">Language</Label>
                  <Select
                    value={language}
                    onValueChange={(v) => setLanguage(v as HuntQueryLanguage)}
                  >
                    <SelectTrigger id="hunt-language">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {(Object.keys(LANGUAGE_LABEL) as HuntQueryLanguage[]).map((k) => (
                        <SelectItem key={k} value={k}>
                          {LANGUAGE_LABEL[k]}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="hunt-lookback">Window</Label>
                  <Select
                    value={String(lookbackHours)}
                    onValueChange={(v) => setLookbackHours(Number(v))}
                  >
                    <SelectTrigger id="hunt-lookback">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {LOOKBACK_OPTIONS.map((opt) => (
                        <SelectItem key={opt.value} value={String(opt.value)}>
                          {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              {/* Phase 4 #4.1 — Translate from English. Only works
                  for KQL / Lucene; Sigma authoring stays manual
                  because the YAML structure isn't a one-line model
                  output. */}
              {language !== "sigma" && (
                <div className="rounded-md border bg-muted/40 p-3">
                  <Label
                    htmlFor="hunt-nl-prompt"
                    className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground"
                  >
                    <Sparkles className="h-3 w-3" aria-hidden="true" />
                    Translate from English
                  </Label>
                  <Textarea
                    id="hunt-nl-prompt"
                    value={nlPrompt}
                    onChange={(e) => setNlPrompt(e.target.value)}
                    rows={2}
                    placeholder="e.g. all bash processes spawning curl in the last hour"
                    spellCheck={false}
                    className="mt-2"
                  />
                  {nlError && (
                    <p className="mt-2 rounded-md border border-destructive/30 bg-destructive/10 px-2 py-1 text-xs text-destructive">
                      {nlError}
                    </p>
                  )}
                  <div className="mt-2">
                    <Button
                      type="button"
                      size="sm"
                      variant="secondary"
                      disabled={!nlPrompt.trim() || nlTranslate.isPending}
                      onClick={() =>
                        nlTranslate.mutate({
                          prompt: nlPrompt.trim(),
                          language: language as "kql" | "lucene",
                        })
                      }
                    >
                      {nlTranslate.isPending ? (
                        <Loader2 className="mr-2 h-3 w-3 animate-spin" aria-hidden="true" />
                      ) : (
                        <Sparkles className="mr-2 h-3 w-3" aria-hidden="true" />
                      )}
                      Translate
                    </Button>
                  </div>
                </div>
              )}
              <div>
                <Label htmlFor="hunt-query">Query body</Label>
                <Textarea
                  id="hunt-query"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  rows={14}
                  placeholder={
                    language === "sigma"
                      ? "title: my hunt\nlogsource:\n  product: linux\ndetection:\n  s:\n    event.category: process\n  condition: s"
                      : "event.category:process AND process.name:bash"
                  }
                  spellCheck={false}
                />
              </div>
              <div>
                <Label htmlFor="hunt-size">Max rows</Label>
                <Input
                  id="hunt-size"
                  type="number"
                  min={1}
                  max={10000}
                  value={size}
                  onChange={(e) => setSize(Number(e.target.value) || 100)}
                />
              </div>
              {error && (
                <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                  {error}
                </p>
              )}
              <div className="flex flex-wrap gap-2">
                <Button type="submit" disabled={runAdhoc.isPending}>
                  {runAdhoc.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                  ) : (
                    <Play className="mr-2 h-4 w-4" aria-hidden="true" />
                  )}
                  Run
                </Button>
                <Button type="button" variant="secondary" onClick={() => setShowSave((s) => !s)}>
                  <Save className="mr-2 h-4 w-4" aria-hidden="true" />
                  Save…
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={!result || result.hits.length === 0}
                  onClick={() => {
                    if (result) downloadCsv("hunt-results.csv", hitsToCsv(result.hits));
                  }}
                >
                  <Download className="mr-2 h-4 w-4" aria-hidden="true" />
                  Export CSV
                </Button>
              </div>
            </form>
            {showSave && (
              <SaveHuntForm
                defaults={{ query_dsl: query, query_language: language }}
                isAdmin={isAdmin}
                onClose={() => setShowSave(false)}
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>
              Results{" "}
              {result && (
                <span className="ml-2 text-xs font-normal text-muted-foreground tabular-nums">
                  {result.total} match{result.total === 1 ? "" : "es"}
                  {result.truncated && ` (showing first ${result.hits.length})`}
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResultGrid result={result} pending={runAdhoc.isPending} />
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function ResultGrid({ result, pending }: { result: HuntRunResult | null; pending: boolean }) {
  if (pending) {
    return <p className="text-sm text-muted-foreground">Running…</p>;
  }
  if (!result) {
    return (
      <p className="text-sm text-muted-foreground">Run a query to see matching telemetry events.</p>
    );
  }
  if (result.hits.length === 0) {
    return <p className="text-sm text-muted-foreground">No matches.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Timestamp</TableHead>
            <TableHead>Host</TableHead>
            <TableHead>Event</TableHead>
            <TableHead>Source</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {result.hits.map((h, idx) => (
            <TableRow key={`${h.event_id ?? idx}-${h.timestamp ?? idx}`}>
              <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                {h.timestamp ?? "—"}
              </TableCell>
              <TableCell className="font-mono text-[11px]">
                {h.host_id ? h.host_id.slice(0, 8) : "—"}
              </TableCell>
              <TableCell className="font-mono text-[11px]">{h.event_id ?? "—"}</TableCell>
              <TableCell>
                <pre className="max-w-md overflow-x-auto rounded bg-muted px-2 py-1 text-[10px]">
                  {JSON.stringify(h.source, null, 0).slice(0, 200)}
                </pre>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

interface SaveDefaults {
  query_dsl: string;
  query_language: HuntQueryLanguage;
}

function SaveHuntForm({
  defaults,
  isAdmin,
  onClose,
}: {
  defaults: SaveDefaults;
  isAdmin: boolean;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scheduleCron, setScheduleCron] = useState("");
  const [alertOnHit, setAlertOnHit] = useState(false);
  const [severity, setSeverity] = useState<HuntSeverity>("medium");
  const [saveError, setSaveError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: huntApi.createSaved,
    onSuccess: () => {
      onClose();
    },
    onError: (err) => setSaveError(err instanceof ApiError ? err.detail : String(err)),
  });

  function onSubmit(e: FormEvent): void {
    e.preventDefault();
    if (!defaults.query_dsl.trim()) {
      setSaveError("query is empty");
      return;
    }
    const body: SavedHuntCreate = {
      name,
      description: description || null,
      query_dsl: defaults.query_dsl,
      query_language: defaults.query_language,
      schedule_cron: scheduleCron || null,
      alert_on_hit: alertOnHit,
      severity: alertOnHit ? severity : null,
    };
    save.mutate(body);
  }

  return (
    <form onSubmit={onSubmit} className="mt-6 space-y-3 rounded-md border p-4">
      <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        Save hunt
      </div>
      <div>
        <Label htmlFor="save-name">Name</Label>
        <Input
          id="save-name"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. suspicious bash → wget"
        />
      </div>
      <div>
        <Label htmlFor="save-description">Description</Label>
        <Input
          id="save-description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Optional"
        />
      </div>
      {isAdmin && (
        <>
          <div>
            <Label htmlFor="save-cron">Schedule (cron, admin-only)</Label>
            <Input
              id="save-cron"
              value={scheduleCron}
              onChange={(e) => setScheduleCron(e.target.value)}
              placeholder="*/15 * * * *"
            />
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="save-alert"
              checked={alertOnHit}
              onCheckedChange={(v) => setAlertOnHit(v === true)}
            />
            <Label htmlFor="save-alert" className="text-sm font-normal">
              Open alerts on scheduled hits (admin-only)
            </Label>
          </div>
          {alertOnHit && (
            <div>
              <Label htmlFor="save-severity">Alert severity</Label>
              <Select value={severity} onValueChange={(v) => setSeverity(v as HuntSeverity)}>
                <SelectTrigger id="save-severity">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(["info", "low", "medium", "high", "critical"] as const).map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
        </>
      )}
      {saveError && (
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          {saveError}
        </p>
      )}
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={save.isPending}>
          Save
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
