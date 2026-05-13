/**
 * Hosts mini-table widget (Phase 3 #3.4).
 *
 * Renders the top-N hosts by last-seen activity. The row links to the
 * full host detail page so the widget remains a quick-jump rather
 * than trying to be a duplicate /hosts console.
 */
import { Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface HostRow {
  id: string;
  hostname: string;
  status: string;
  os_family: string;
  last_seen_at: string | null;
}

interface Props {
  data: HostRow[] | null;
}

export function HostsTableWidget({ data }: Props) {
  const rows = data ?? [];
  return (
    <Card className="h-full">
      <CardContent className="flex h-full flex-col p-4">
        <div className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Hosts
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hostname</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>OS</TableHead>
                <TableHead>Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-muted-foreground">
                    No hosts.
                  </TableCell>
                </TableRow>
              )}
              {rows.map((h) => (
                <TableRow key={h.id}>
                  <TableCell>
                    <Link to={`/hosts/${h.id}`} className="font-medium hover:underline">
                      {h.hostname}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-[10px] uppercase">
                      {h.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{h.os_family}</TableCell>
                  <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                    {h.last_seen_at ? new Date(h.last_seen_at).toLocaleString() : "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
