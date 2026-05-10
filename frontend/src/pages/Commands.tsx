import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useState } from "react";
import { commandsApi } from "@/api/commands";
import { Badge } from "@/components/ui/badge";
import { Select } from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/PageHeader";
import type { CommandKind, CommandStatus } from "@/types/api";

const STATUS_VARIANT: Record<CommandStatus, "default" | "secondary" | "destructive" | "outline" | "success" | "warning"> = {
  pending: "warning",
  dispatched: "default",
  succeeded: "success",
  failed: "destructive",
};

const PAYLOAD_RENDER = (kind: CommandKind, payload: Record<string, unknown>): string => {
  if (kind === "kill_process") return `pid=${payload.pid ?? "?"}`;
  if ("pattern" in payload) return String(payload.pattern);
  return JSON.stringify(payload);
};

export function Commands() {
  const [statusFilter, setStatusFilter] = useState<CommandStatus | "">("");
  const [kindFilter, setKindFilter] = useState<CommandKind | "">("");

  const { data, isLoading } = useQuery({
    queryKey: ["commands", { statusFilter, kindFilter }],
    queryFn: () =>
      commandsApi.listAll({
        status_: statusFilter || undefined,
        kind: kindFilter || undefined,
        limit: 100,
      }),
    refetchInterval: 5000, // poll while pending/dispatched commands resolve
  });

  return (
    <>
      <PageHeader
        title="Commands"
        description={`${data?.total ?? 0} response actions across visible hosts`}
      />
      <div className="flex flex-wrap gap-3 px-8 pt-6">
        <Select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as CommandStatus | "")}
        >
          <option value="">all statuses</option>
          <option value="pending">pending</option>
          <option value="dispatched">dispatched</option>
          <option value="succeeded">succeeded</option>
          <option value="failed">failed</option>
        </Select>
        <Select
          value={kindFilter}
          onChange={(e) => setKindFilter(e.target.value as CommandKind | "")}
        >
          <option value="">all kinds</option>
          <option value="kill_process">kill_process</option>
          <option value="block_process">block_process</option>
          <option value="block_file">block_file</option>
          <option value="unblock_process">unblock_process</option>
          <option value="unblock_file">unblock_file</option>
        </Select>
      </div>
      <div className="px-8 py-6">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Created</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Payload</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Completed</TableHead>
                <TableHead>Error</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    loading...
                  </TableCell>
                </TableRow>
              )}
              {data?.items.length === 0 && !isLoading && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    no commands match the current filters
                  </TableCell>
                </TableRow>
              )}
              {data?.items.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="font-mono text-xs">
                    {new Date(c.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <Link to={`/hosts/${c.host_id}`} className="font-mono text-xs hover:underline">
                      {c.host_id.slice(0, 8)}...
                    </Link>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{c.kind}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs max-w-md truncate">
                    {PAYLOAD_RENDER(c.kind, c.payload)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={STATUS_VARIANT[c.status]}>{c.status}</Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {c.completed_at ? new Date(c.completed_at).toLocaleString() : "—"}
                  </TableCell>
                  <TableCell className="text-xs text-destructive max-w-xs truncate">
                    {c.error ?? ""}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </>
  );
}
