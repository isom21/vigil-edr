/**
 * Create-a-Job modal — schema-driven form.
 *
 * Each JobKind declares a typed field list; the form renders the right
 * input per field kind and emits the JSON shape the backend expects.
 * No more "edit this JSON example" textarea — operators don't have to
 * remember whether `recurse` is a boolean or a string or what
 * `max_size_bytes` defaults to.
 *
 * Scope: three options — all online, host autocomplete (multi-select
 * with chips against /api/hosts?q=…), or host-group from
 * /api/host-groups. The host_ids legacy free-text input is gone.
 */
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { X } from "lucide-react";
import { ApiError } from "@/api/client";
import { hostGroupsApi } from "@/api/hostGroups";
import { hostsApi } from "@/api/hosts";
import { jobsApi } from "@/api/jobs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import type { Host, JobKind, JobScopeKind } from "@/types/api";

// ---------- Schema ----------

type FieldKind = "text" | "number" | "boolean" | "string-list";

interface FieldDef {
  /** JSON key emitted in the parameters object. */
  key: string;
  /** Visible label above the input. */
  label: string;
  kind: FieldKind;
  /** Default form value. For string-list, an array. */
  defaultValue: unknown;
  placeholder?: string;
  hint?: string;
  /** Required gate — empty values for required fields block submit. */
  required?: boolean;
  /** Numeric input bounds (UI only; backend re-validates). */
  min?: number;
  max?: number;
}

interface KindMeta {
  label: string;
  group: "Containment" | "Survey" | "Hunt" | "Acquisition" | "Diagnostic" | "Bulk";
  /** Short copy under the kind picker. */
  hint?: string;
  adminOnly?: boolean;
  fields: FieldDef[];
}

const KIND_META: Partial<Record<JobKind, KindMeta>> = {
  host_sweep: {
    label: "Host sweep",
    group: "Bulk",
    hint: "Bundle of survey collectors. Empty categories = the default set.",
    fields: [
      {
        key: "categories",
        label: "Categories",
        kind: "string-list",
        defaultValue: [],
        placeholder: "process, persistence, …",
        hint: "Leave empty for the default survey set.",
      },
    ],
  },
  process_snapshot: {
    label: "Process snapshot",
    group: "Survey",
    hint: "Running process tree at job time.",
    fields: [],
  },
  network_snapshot: {
    label: "Network snapshot",
    group: "Survey",
    hint: "Established + listening sockets.",
    fields: [],
  },
  account_audit: {
    label: "Account audit",
    group: "Survey",
    hint: "Local user/group/SSH-authorized-keys inventory.",
    fields: [],
  },
  agent_diagnostic: {
    label: "Agent diagnostic",
    group: "Survey",
    hint: "Agent version + host metadata + memory.",
    fields: [],
  },
  hash_files: {
    label: "Hash files",
    group: "Hunt",
    hint: "SHA-256 every file under path. Default max 64 MiB per file.",
    fields: [
      {
        key: "path",
        label: "Path",
        kind: "text",
        defaultValue: "/etc",
        required: true,
        placeholder: "/etc",
      },
      { key: "recurse", label: "Recurse", kind: "boolean", defaultValue: true },
      {
        key: "max_size_bytes",
        label: "Max size per file (bytes)",
        kind: "number",
        defaultValue: 67_108_864,
        min: 1,
        hint: "64 MiB default. Files above this are skipped.",
      },
    ],
  },
  yara_fs_scan: {
    label: "YARA filesystem scan",
    group: "Hunt",
    hint: "Empty rule_ids = use every cached enabled YARA rule.",
    fields: [
      { key: "path", label: "Path", kind: "text", defaultValue: "/tmp", required: true },
      { key: "recurse", label: "Recurse", kind: "boolean", defaultValue: true },
      {
        key: "rule_ids",
        label: "Rule ids",
        kind: "string-list",
        defaultValue: [],
        placeholder: "uuid, uuid, …",
        hint: "Leave empty for all enabled YARA rules.",
      },
    ],
  },
  ioc_sweep: {
    label: "IOC sweep",
    group: "Hunt",
    hint: "Hash + filename + filepath IOCs from the active ruleset.",
    fields: [
      { key: "path", label: "Path", kind: "text", defaultValue: "/usr/bin", required: true },
      { key: "recurse", label: "Recurse", kind: "boolean", defaultValue: true },
    ],
  },
  file_acquire: {
    label: "Acquire files",
    group: "Acquisition",
    hint: "Up to 200 paths. Each becomes its own artifact.",
    fields: [
      {
        key: "paths",
        label: "Paths",
        kind: "string-list",
        defaultValue: ["/var/log/auth.log"],
        required: true,
        placeholder: "/var/log/auth.log",
      },
      {
        key: "max_size_bytes",
        label: "Max size per file (bytes)",
        kind: "number",
        defaultValue: 268_435_456,
        min: 1,
        hint: "256 MiB default.",
      },
    ],
  },
  crash_dump_collect: {
    label: "Collect crash dumps",
    group: "Acquisition",
    hint: "Scans /var/crash, systemd-coredump, Windows Minidump.",
    fields: [],
  },
  event_log_acquire: {
    label: "Acquire event log",
    group: "Acquisition",
    hint: "Linux: journalctl. Windows: System / Application / Security.",
    fields: [
      {
        key: "hours",
        label: "Lookback (hours)",
        kind: "number",
        defaultValue: 24,
        min: 1,
        max: 168,
      },
    ],
  },
  triage_collect: {
    label: "Disk forensics triage",
    group: "Acquisition",
    hint: "Bundle registry, MFT, prefetch, browser, event logs, persistence into one ZIP.",
    adminOnly: true,
    fields: [
      {
        key: "include_registry",
        label: "Registry hives (Windows)",
        kind: "boolean",
        defaultValue: true,
      },
      {
        key: "include_mft",
        label: "MFT (Windows)",
        kind: "boolean",
        defaultValue: true,
      },
      {
        key: "include_prefetch",
        label: "Prefetch (Windows)",
        kind: "boolean",
        defaultValue: true,
      },
      {
        key: "include_browser",
        label: "Browser history",
        kind: "boolean",
        defaultValue: true,
      },
      {
        key: "include_event_log",
        label: "Event logs (Windows)",
        kind: "boolean",
        defaultValue: true,
      },
      {
        key: "include_systemd_journal",
        label: "systemd journal (Linux)",
        kind: "boolean",
        defaultValue: true,
      },
      {
        key: "include_persistence",
        label: "Persistence artifacts",
        kind: "boolean",
        defaultValue: true,
      },
      {
        key: "max_size_mb",
        label: "Archive cap (MiB)",
        kind: "number",
        defaultValue: 2048,
        min: 16,
        max: 16384,
      },
    ],
  },
  shell_command: {
    label: "Shell command",
    group: "Diagnostic",
    hint: "Admin-only. Allow-listed binaries: ps, ss, ip, dig, whoami, ipconfig, …",
    adminOnly: true,
    fields: [
      {
        key: "command",
        label: "Command",
        kind: "text",
        defaultValue: "whoami",
        required: true,
        placeholder: "whoami",
      },
      {
        key: "args",
        label: "Arguments",
        kind: "string-list",
        defaultValue: [],
        placeholder: "-l, -a",
      },
      {
        key: "timeout_seconds",
        label: "Timeout (s)",
        kind: "number",
        defaultValue: 30,
        min: 1,
        max: 300,
      },
    ],
  },
  // Containment kinds (kill_process / delete_file / isolate / unisolate
  // / quarantine_file / release_quarantine) are intentionally NOT
  // surfaced here. The agent registers no JobHandler for them on
  // either platform (verified live: the Linux dispatcher returns
  // "no handler for kind 'kill_process' on linux") — they're carried
  // by the legacy Commands flow (`Body::KillProcess`, `Body::Isolate`,
  // etc.) and exposed in the UI through `<CommandDialog>` from the
  // alert detail rail + host detail page. Listing them here would
  // surface a kind operators can pick but the agent will refuse.
};

const KINDS_ORDERED: JobKind[] = (Object.keys(KIND_META) as JobKind[]).sort((a, b) => {
  const A = KIND_META[a]!;
  const B = KIND_META[b]!;
  if (!!A.adminOnly !== !!B.adminOnly) return A.adminOnly ? 1 : -1;
  if (A.group !== B.group) return A.group.localeCompare(B.group);
  return A.label.localeCompare(B.label);
});

// ---------- Helpers ----------

function defaultsFor(fields: FieldDef[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) out[f.key] = f.defaultValue;
  return out;
}

function emitParams(fields: FieldDef[], values: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    let v = values[f.key];
    if (f.kind === "string-list") {
      // Already an array in form state. Drop empty/whitespace-only entries.
      v = ((v as string[]) ?? []).map((s) => s.trim()).filter(Boolean);
    }
    out[f.key] = v;
  }
  return out;
}

function fieldsValid(fields: FieldDef[], values: Record<string, unknown>): boolean {
  for (const f of fields) {
    if (!f.required) continue;
    const v = values[f.key];
    if (f.kind === "text" && !((v as string) ?? "").trim()) return false;
    if (f.kind === "number" && (v === "" || v === null || v === undefined)) return false;
    if (f.kind === "string-list" && ((v as string[]) ?? []).every((s) => !s.trim())) return false;
  }
  return true;
}

// ---------- Component ----------

export function JobCreateModal({
  onClose,
  onCreated,
  presetHostId,
}: {
  onClose: () => void;
  onCreated: (jobId: string) => void;
  presetHostId?: string;
}) {
  const [kind, setKind] = useState<JobKind>("host_sweep");
  const meta = KIND_META[kind]!;
  const [values, setValues] = useState<Record<string, unknown>>(() => defaultsFor(meta.fields));
  const [scopeKind, setScopeKind] = useState<JobScopeKind>(
    presetHostId ? "host_ids" : "all_online",
  );
  const [selectedHosts, setSelectedHosts] = useState<Host[]>([]);
  const [groupId, setGroupId] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  // Reset value defaults when kind changes — analysts can edit away
  // but the previous kind's keys shouldn't leak.
  useEffect(() => {
    setValues(defaultsFor(meta.fields));
    setError(null);
  }, [kind, meta.fields]);

  // Pre-fill the host chip set from presetHostId (called from
  // HostDetail or similar). Looks the host up so we display its
  // hostname rather than a bare UUID chip.
  const presetHostQ = useQuery({
    queryKey: ["host", presetHostId],
    queryFn: () => hostsApi.get(presetHostId!),
    enabled: !!presetHostId && selectedHosts.length === 0,
  });
  useEffect(() => {
    if (presetHostQ.data && selectedHosts.length === 0) {
      setSelectedHosts([presetHostQ.data]);
    }
  }, [presetHostQ.data, selectedHosts.length]);

  const create = useMutation({
    mutationFn: () => {
      if (!fieldsValid(meta.fields, values)) {
        throw new Error("required parameter is empty");
      }
      const parameters = emitParams(meta.fields, values);
      let scope;
      if (scopeKind === "host_ids") {
        if (selectedHosts.length === 0) throw new Error("pick at least one host");
        scope = { kind: scopeKind, host_ids: selectedHosts.map((h) => h.id) };
      } else if (scopeKind === "host_group") {
        if (!groupId) throw new Error("pick a host group");
        scope = { kind: scopeKind, group_id: groupId };
      } else {
        scope = { kind: scopeKind };
      }
      return jobsApi.create({ kind, parameters, scope });
    },
    onSuccess: (detail) => onCreated(detail.id),
    onError: (e) =>
      setError(e instanceof ApiError ? e.detail : ((e as Error).message ?? String(e))),
  });

  const grouped = useMemo(() => {
    const out: Record<string, JobKind[]> = {};
    for (const k of KINDS_ORDERED) {
      const g = KIND_META[k]!.group;
      (out[g] ??= []).push(k);
    }
    return out;
  }, []);

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Create job</DialogTitle>
          <DialogDescription>
            Job lifecycle is per host — pick scope then watch the run table fill in.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="job-kind">Kind</Label>
            <Select id="job-kind" value={kind} onChange={(e) => setKind(e.target.value as JobKind)}>
              {Object.entries(grouped).map(([group, ks]) => (
                <optgroup key={group} label={group}>
                  {ks.map((k) => (
                    <option key={k} value={k}>
                      {KIND_META[k]!.label}
                      {KIND_META[k]!.adminOnly ? " · admin" : ""}
                    </option>
                  ))}
                </optgroup>
              ))}
            </Select>
            {meta.hint && <p className="text-xs text-muted-foreground">{meta.hint}</p>}
          </div>

          {meta.fields.length > 0 && (
            <div className="space-y-3 rounded-md border bg-muted/20 p-3">
              {meta.fields.map((f) => (
                <FieldRow
                  key={f.key}
                  field={f}
                  value={values[f.key]}
                  onChange={(v) => setValues((prev) => ({ ...prev, [f.key]: v }))}
                />
              ))}
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="job-scope">Scope</Label>
            <Select
              id="job-scope"
              value={scopeKind}
              onChange={(e) => setScopeKind(e.target.value as JobScopeKind)}
            >
              <option value="all_online">All online hosts</option>
              <option value="host_ids">Specific hosts</option>
              <option value="host_group">Host group</option>
            </Select>
            {scopeKind === "host_ids" && (
              <HostMultiSelect selected={selectedHosts} onChange={setSelectedHosts} />
            )}
            {scopeKind === "host_group" && (
              <HostGroupSelect value={groupId} onChange={setGroupId} />
            )}
          </div>

          {error && (
            <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={create.isPending}>
            Cancel
          </Button>
          <Button onClick={() => create.mutate()} disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create job"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------- Field renderer ----------

function FieldRow({
  field,
  value,
  onChange,
}: {
  field: FieldDef;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  const id = `job-field-${field.key}`;
  return (
    <div className="space-y-1">
      <Label htmlFor={id} className="text-xs">
        {field.label}
        {field.required && <span className="ml-1 text-destructive">*</span>}
      </Label>
      {field.kind === "text" && (
        <Input
          id={id}
          value={(value as string) ?? ""}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className="font-mono text-xs"
        />
      )}
      {field.kind === "number" && (
        <Input
          id={id}
          type="number"
          value={(value as number | string) ?? ""}
          onChange={(e) => onChange(e.target.value === "" ? "" : Number(e.target.value))}
          min={field.min}
          max={field.max}
          className="font-mono text-xs"
        />
      )}
      {field.kind === "boolean" && (
        <div className="flex items-center gap-2">
          <input
            id={id}
            type="checkbox"
            checked={!!value}
            onChange={(e) => onChange(e.target.checked)}
          />
          <span className="text-xs text-muted-foreground">{field.placeholder ?? ""}</span>
        </div>
      )}
      {field.kind === "string-list" && (
        <StringListField
          id={id}
          value={(value as string[]) ?? []}
          onChange={onChange}
          placeholder={field.placeholder}
        />
      )}
      {field.hint && <p className="text-[11px] text-muted-foreground">{field.hint}</p>}
    </div>
  );
}

function StringListField({
  id,
  value,
  onChange,
  placeholder,
}: {
  id: string;
  value: string[];
  onChange: (v: unknown) => void;
  placeholder?: string;
}) {
  // Render as one input per entry plus an Add button. Splits on comma
  // when pasted so an analyst pasting a CSV doesn't have to add one
  // entry at a time.
  const entries = value.length === 0 ? [""] : value;
  return (
    <div className="space-y-1">
      {entries.map((v, i) => (
        <div key={i} className="flex items-center gap-1">
          <Input
            id={i === 0 ? id : undefined}
            value={v}
            onChange={(e) => {
              const text = e.target.value;
              if (text.includes(",")) {
                const parts = text
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean);
                const next = [...entries];
                next.splice(i, 1, ...parts);
                onChange(next);
              } else {
                const next = [...entries];
                next[i] = text;
                onChange(next);
              }
            }}
            placeholder={placeholder}
            className="font-mono text-xs"
          />
          {entries.length > 1 && (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-label="Remove entry"
              onClick={() => {
                const next = entries.filter((_, j) => j !== i);
                onChange(next);
              }}
            >
              <X className="h-3 w-3" />
            </Button>
          )}
        </div>
      ))}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-7 text-xs"
        onClick={() => onChange([...entries, ""])}
      >
        + Add entry
      </Button>
    </div>
  );
}

// ---------- Host multi-select ----------

function HostMultiSelect({
  selected,
  onChange,
}: {
  selected: Host[];
  onChange: (next: Host[]) => void;
}) {
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q.trim()), 200);
    return () => clearTimeout(t);
  }, [q]);

  const search = useQuery({
    queryKey: ["host-search", debouncedQ],
    queryFn: () => hostsApi.list({ q: debouncedQ, limit: 10 }),
    enabled: debouncedQ.length >= 2,
  });

  const selectedIds = new Set(selected.map((h) => h.id));
  const candidates = (search.data?.items ?? []).filter((h) => !selectedIds.has(h.id));

  return (
    <div className="space-y-2">
      {selected.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {selected.map((h) => (
            <span
              key={h.id}
              className="inline-flex items-center gap-1 rounded-full border bg-secondary/50 px-2 py-0.5 text-xs"
            >
              {h.hostname}
              <button
                type="button"
                aria-label={`Remove ${h.hostname}`}
                onClick={() => onChange(selected.filter((s) => s.id !== h.id))}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
        </div>
      )}
      <div className="relative">
        <Input
          placeholder="Search hosts by hostname… (min 2 chars)"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        {debouncedQ.length >= 2 && candidates.length > 0 && (
          <div className="absolute z-10 mt-1 w-full overflow-hidden rounded-md border bg-popover shadow-md">
            {candidates.map((h) => (
              <button
                key={h.id}
                type="button"
                onClick={() => {
                  onChange([...selected, h]);
                  setQ("");
                }}
                className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs hover:bg-accent"
              >
                <span>{h.hostname}</span>
                <span className="text-muted-foreground">{h.status}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      {selected.length === 0 && (
        <p className="text-[11px] text-muted-foreground">
          Pick one or more hosts — the job fans out a run per host.
        </p>
      )}
    </div>
  );
}

// ---------- Host-group select ----------

function HostGroupSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const groupsQ = useQuery({
    queryKey: ["host-groups", { limit: 200 }],
    queryFn: () => hostGroupsApi.list({ limit: 200 }),
  });
  return (
    <Select value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">— pick a group —</option>
      {groupsQ.data?.items.map((g) => (
        <option key={g.id} value={g.id}>
          {g.name} · {g.host_count} host{g.host_count === 1 ? "" : "s"}
        </option>
      ))}
    </Select>
  );
}
