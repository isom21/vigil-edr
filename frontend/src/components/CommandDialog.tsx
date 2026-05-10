import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { commandsApi } from "@/api/commands";
import { ApiError } from "@/api/client";
import type { CommandKind } from "@/types/api";

const KINDS: { value: CommandKind; label: string; payloadField: "pid" | "pattern"; placeholder: string }[] = [
  { value: "kill_process",     label: "Kill process",     payloadField: "pid",     placeholder: "1234" },
  { value: "block_process",    label: "Block process",    payloadField: "pattern", placeholder: "C:\\Users\\evil.exe or /usr/local/bin/evil" },
  { value: "block_file",       label: "Block file",       payloadField: "pattern", placeholder: "C:\\Path\\to\\file.dll or /etc/secret.conf" },
  { value: "unblock_process",  label: "Unblock process",  payloadField: "pattern", placeholder: "(must match an existing block pattern)" },
  { value: "unblock_file",     label: "Unblock file",     payloadField: "pattern", placeholder: "(must match an existing block pattern)" },
];

interface Props {
  hostId: string;
  /** Triggers can be a button rendered by the parent. */
  trigger?: React.ReactNode;
  /** Optional default kind / payload for context-driven dialogs (e.g. AlertDetail). */
  defaultKind?: CommandKind;
  defaultPattern?: string;
  defaultPid?: number;
}

export function CommandDialog({ hostId, trigger, defaultKind, defaultPattern, defaultPid }: Props) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<CommandKind>(defaultKind ?? "block_process");
  const [pid, setPid] = useState<string>(defaultPid !== undefined ? String(defaultPid) : "");
  const [pattern, setPattern] = useState<string>(defaultPattern ?? "");
  const [error, setError] = useState<string | null>(null);
  const qc = useQueryClient();

  const meta = KINDS.find((k) => k.value === kind)!;

  const mutation = useMutation({
    mutationFn: () => {
      const payload: Record<string, unknown> = {};
      if (meta.payloadField === "pid") {
        const n = parseInt(pid, 10);
        if (!n || n <= 0) throw new ApiError(400, "pid must be a positive integer");
        payload.pid = n;
      } else {
        if (!pattern.trim()) throw new ApiError(400, "pattern is required");
        payload.pattern = pattern.trim();
      }
      return commandsApi.queue(hostId, { kind, payload });
    },
    onSuccess: () => {
      setOpen(false);
      setError(null);
      qc.invalidateQueries({ queryKey: ["commands"] });
      qc.invalidateQueries({ queryKey: ["host-commands", hostId] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger ?? <Button>Queue command</Button>}</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Queue response action</DialogTitle>
          <DialogDescription>
            Sends a command to the agent on the next gRPC round-trip (typically &lt;1s).
            Result lands on /commands once the agent confirms.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div>
            <Label htmlFor="cmd-kind">Action</Label>
            <select
              id="cmd-kind"
              value={kind}
              onChange={(e) => setKind(e.target.value as CommandKind)}
              className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            >
              {KINDS.map((k) => (
                <option key={k.value} value={k.value}>{k.label}</option>
              ))}
            </select>
          </div>
          {meta.payloadField === "pid" ? (
            <div>
              <Label htmlFor="cmd-pid">PID</Label>
              <Input
                id="cmd-pid"
                value={pid}
                onChange={(e) => setPid(e.target.value)}
                placeholder={meta.placeholder}
                inputMode="numeric"
              />
            </div>
          ) : (
            <div>
              <Label htmlFor="cmd-pattern">Pattern</Label>
              <Input
                id="cmd-pattern"
                value={pattern}
                onChange={(e) => setPattern(e.target.value)}
                placeholder={meta.placeholder}
              />
              <p className="mt-1 text-xs text-muted-foreground">
                Linux: full executable path. Windows: case-insensitive substring of the image path.
              </p>
            </div>
          )}
          {error && (
            <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
            {mutation.isPending ? "Queueing..." : "Queue"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
