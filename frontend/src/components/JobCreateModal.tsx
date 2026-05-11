/**
 * Create-a-Job modal (M23.i).
 *
 * Two layers of input:
 *   1. Kind picker — one of ~30 JobKinds.
 *   2. Per-kind params: a JSON textarea pre-filled with the shape we
 *      expect on the manager (the hint below the kind picker shows
 *      the example), so analysts don't have to grep the proto.
 *   3. Scope picker — single host id list, group, or "all online".
 *
 * The form does no parameter validation client-side; the manager
 * rejects bad shapes with 422 and we surface that inline.
 */
import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { ApiError } from "@/api/client";
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
import { Textarea } from "@/components/ui/textarea";
import type { JobKind, JobScopeKind } from "@/types/api";

interface KindMeta {
  label: string;
  group: "Containment" | "Survey" | "Hunt" | "Acquisition" | "Diagnostic" | "Bulk";
  paramsExample: string;
  paramsHint: string;
  adminOnly?: boolean;
}

// Curated set of kinds the UI knows how to scaffold. Anything not
// listed here is still creatable via the wire API.
const KIND_META: Partial<Record<JobKind, KindMeta>> = {
  host_sweep: {
    label: "Host sweep",
    group: "Bulk",
    paramsExample: '{"categories": []}',
    paramsHint: "Empty list = use the default survey set.",
  },
  process_snapshot: {
    label: "Process snapshot",
    group: "Survey",
    paramsExample: "{}",
    paramsHint: "No parameters.",
  },
  network_snapshot: {
    label: "Network snapshot",
    group: "Survey",
    paramsExample: "{}",
    paramsHint: "No parameters.",
  },
  account_audit: {
    label: "Account audit",
    group: "Survey",
    paramsExample: "{}",
    paramsHint: "No parameters.",
  },
  agent_diagnostic: {
    label: "Agent diagnostic",
    group: "Survey",
    paramsExample: "{}",
    paramsHint: "Agent version + host metadata + memory.",
  },
  hash_files: {
    label: "Hash files",
    group: "Hunt",
    paramsExample: '{"path": "/etc", "recurse": true, "max_size_bytes": 67108864}',
    paramsHint: "SHA-256 every file under path. Default max 64 MiB per file.",
  },
  yara_fs_scan: {
    label: "YARA filesystem scan",
    group: "Hunt",
    paramsExample: '{"path": "/tmp", "recurse": true, "rule_ids": []}',
    paramsHint: "Empty rule_ids = use every cached enabled YARA rule.",
  },
  ioc_sweep: {
    label: "IOC sweep",
    group: "Hunt",
    paramsExample: '{"path": "/usr/bin", "recurse": true}',
    paramsHint: "Hash + filename + filepath IOCs from the active ruleset.",
  },
  file_acquire: {
    label: "Acquire files",
    group: "Acquisition",
    paramsExample: '{"paths": ["/var/log/auth.log"], "max_size_bytes": 268435456}',
    paramsHint: "Up to 200 paths. Each becomes its own artifact.",
  },
  crash_dump_collect: {
    label: "Collect crash dumps",
    group: "Acquisition",
    paramsExample: "{}",
    paramsHint: "Scans /var/crash, systemd-coredump, Windows Minidump.",
  },
  event_log_acquire: {
    label: "Acquire event log",
    group: "Acquisition",
    paramsExample: '{"hours": 24}',
    paramsHint: "Linux: journalctl. Windows: System/Application/Security.",
  },
  shell_command: {
    label: "Shell command",
    group: "Diagnostic",
    paramsExample: '{"command": "whoami", "args": [], "timeout_seconds": 30}',
    paramsHint: "Admin-only. Allow-listed binaries: ps, ss, ip, dig, whoami, ipconfig, …",
    adminOnly: true,
  },
  kill_process: {
    label: "Kill process",
    group: "Containment",
    paramsExample: '{"pid": 1234}',
    paramsHint: "Admin-only.",
    adminOnly: true,
  },
  delete_file: {
    label: "Delete file",
    group: "Containment",
    paramsExample: '{"path": "/tmp/mal.bin"}',
    paramsHint: "Admin-only. Irreversible — operator confirmation is on you.",
    adminOnly: true,
  },
  isolate: {
    label: "Isolate host",
    group: "Containment",
    paramsExample: '{"isolate": true, "allowlist_ips": []}',
    paramsHint: "Admin-only. Cuts every connection except allowlist + manager.",
    adminOnly: true,
  },
  unisolate: {
    label: "Unisolate host",
    group: "Containment",
    paramsExample: '{"isolate": false}',
    paramsHint: "Admin-only. Restore connectivity.",
    adminOnly: true,
  },
};

// Order kinds with admin-only at the bottom so analysts see their
// most common picks first.
const KINDS_ORDERED: JobKind[] = (Object.keys(KIND_META) as JobKind[]).sort((a, b) => {
  const A = KIND_META[a]!;
  const B = KIND_META[b]!;
  if (!!A.adminOnly !== !!B.adminOnly) return A.adminOnly ? 1 : -1;
  if (A.group !== B.group) return A.group.localeCompare(B.group);
  return A.label.localeCompare(B.label);
});

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
  const [params, setParams] = useState(meta.paramsExample);
  const [scopeKind, setScopeKind] = useState<JobScopeKind>(
    presetHostId ? "host_ids" : "all_online",
  );
  const [hostIds, setHostIds] = useState(presetHostId ?? "");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => {
      let parsed: Record<string, unknown> = {};
      try {
        parsed = params.trim() ? JSON.parse(params) : {};
      } catch (e) {
        throw new Error(`parameters: ${(e as Error).message}`);
      }
      const scope =
        scopeKind === "host_ids"
          ? {
              kind: scopeKind,
              host_ids: hostIds
                .split(/[,\s]+/)
                .map((s) => s.trim())
                .filter(Boolean),
            }
          : { kind: scopeKind };
      return jobsApi.create({ kind, parameters: parsed, scope });
    },
    onSuccess: (detail) => onCreated(detail.id),
    onError: (e) =>
      setError(e instanceof ApiError ? e.detail : ((e as Error).message ?? String(e))),
  });

  // Reset the params field when the kind changes — analysts can edit
  // away from the example, but switching kind should not leave stale
  // text from the previous kind.
  function onKindChange(next: JobKind) {
    setKind(next);
    setParams(KIND_META[next]!.paramsExample);
    setError(null);
  }

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
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Create job</DialogTitle>
          <DialogDescription>
            Job lifecycle is per host — pick scope then watch the run table fill in.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="job-kind">Kind</Label>
            <Select
              id="job-kind"
              value={kind}
              onChange={(e) => onKindChange(e.target.value as JobKind)}
            >
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
            <p className="text-xs text-muted-foreground">{meta.paramsHint}</p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="job-params">Parameters (JSON)</Label>
            <Textarea
              id="job-params"
              value={params}
              onChange={(e) => setParams(e.target.value)}
              className="font-mono text-xs"
              rows={6}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="job-scope">Scope</Label>
            <Select
              id="job-scope"
              value={scopeKind}
              onChange={(e) => setScopeKind(e.target.value as JobScopeKind)}
            >
              <option value="all_online">All online hosts</option>
              <option value="host_ids">Specific host ids</option>
            </Select>
            {scopeKind === "host_ids" && (
              <Input
                placeholder="comma- or space-separated host UUIDs"
                value={hostIds}
                onChange={(e) => setHostIds(e.target.value)}
                className="font-mono text-xs"
              />
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
