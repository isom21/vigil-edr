/**
 * Incidents mini-table widget (Phase 3 #3.4).
 */
import { Link } from "react-router-dom";

import { SeverityBadge } from "@/components/badges";
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
import type { Severity } from "@/types/api";

interface IncidentRow {
  id: string;
  title: string;
  severity: string;
  status: string;
  opened_at: string | null;
  host_hostname: string | null;
}

interface Props {
  data: IncidentRow[] | null;
}

export function IncidentsTableWidget({ data }: Props) {
  const rows = data ?? [];
  return (
    <Card className="h-full">
      <CardContent className="flex h-full flex-col p-4">
        <div className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Incidents
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Title</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Opened</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground">
                    No incidents.
                  </TableCell>
                </TableRow>
              )}
              {rows.map((i) => (
                <TableRow key={i.id}>
                  <TableCell>
                    <Link to={`/incidents/${i.id}`} className="font-medium hover:underline">
                      {i.title}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={i.severity as Severity} />
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-[10px] uppercase">
                      {i.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {i.host_hostname ?? "—"}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                    {i.opened_at ? new Date(i.opened_at).toLocaleString() : "—"}
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
