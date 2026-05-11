/**
 * M20.c host quarantine inventory + release UI.
 *
 * Lists `QuarantinedFile` rows for the host and exposes a Release
 * button that queues a RELEASE_QUARANTINE command via the manager.
 * The row flips to `released` only after the agent confirms (handled
 * by the backend quarantine worker), so the UI invalidates the list
 * and lets react-query refetch.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError } from "@/api/client";
import { quarantineApi } from "@/api/quarantine";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { QuarantinedFile, QuarantineStatus } from "@/types/api";

interface Props {
  hostId: string;
}

const STATUS_CLASS: Record<QuarantineStatus, string> = {
  active: "bg-amber-500/15 text-amber-500 border-amber-500/30",
  released: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  deleted: "bg-muted text-muted-foreground border-border",
};

export function HostQuarantinePanel({ hostId }: Props) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["host-quarantined", hostId],
    queryFn: () => quarantineApi.listForHost(hostId, { limit: 50 }),
  });

  const release = useMutation({
    mutationFn: (id: string) => quarantineApi.release(id, {}),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["host-quarantined", hostId] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const items = data?.items ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Quarantined files ({data?.total ?? 0})</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {isLoading && <p className="text-sm text-muted-foreground">loading…</p>}
        {!isLoading && items.length === 0 && (
          <p className="text-sm text-muted-foreground">No files quarantined on this host.</p>
        )}
        {error && (
          <div className="rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}
        {items.length > 0 && (
          <div className="overflow-auto rounded-md border">
            <table className="w-full text-xs">
              <thead className="bg-muted/40">
                <tr className="border-b">
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Original path
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">SHA-256</th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Quarantined
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">Status</th>
                  <th className="px-3 py-2 text-right font-medium text-muted-foreground">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((f) => (
                  <QuarantineRow
                    key={f.id}
                    file={f}
                    onRelease={() => release.mutate(f.id)}
                    pending={release.isPending && release.variables === f.id}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function QuarantineRow({
  file,
  onRelease,
  pending,
}: {
  file: QuarantinedFile;
  onRelease: () => void;
  pending: boolean;
}) {
  return (
    <tr className="border-b border-border/40 align-top">
      <td className="px-3 py-2 font-mono break-all">{file.original_path}</td>
      <td className="px-3 py-2 font-mono text-muted-foreground" title={file.sha256}>
        {file.sha256.slice(0, 12)}…
      </td>
      <td className="px-3 py-2 whitespace-nowrap text-muted-foreground">
        {new Date(file.quarantined_at).toLocaleString()}
      </td>
      <td className="px-3 py-2">
        <span
          className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium ${STATUS_CLASS[file.status]}`}
        >
          {file.status}
        </span>
      </td>
      <td className="px-3 py-2 text-right">
        {file.status === "active" ? (
          <Button size="sm" variant="outline" onClick={onRelease} disabled={pending}>
            {pending ? "Releasing…" : "Release"}
          </Button>
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </td>
    </tr>
  );
}
