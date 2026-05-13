/**
 * Widget dispatcher (Phase 3 #3.4).
 *
 * Switches off the widget's `type` discriminator and renders the
 * matching component. When the server returns a per-widget error
 * (e.g. an OpenSearch hiccup for a future kind), we render a small
 * error card so the rest of the grid stays usable.
 */
import { Card, CardContent } from "@/components/ui/card";

import { HostStatusWidget } from "./HostStatusWidget";
import { HostsTableWidget } from "./HostsTableWidget";
import { IncidentsTableWidget } from "./IncidentsTableWidget";
import { KpiWidget } from "./KpiWidget";
import { SeverityDonutWidget } from "./SeverityDonutWidget";
import { StateDonutWidget } from "./StateDonutWidget";
import { Timeline24hWidget } from "./Timeline24hWidget";
import { TopRulesWidget } from "./TopRulesWidget";
import type { Widget, WidgetData } from "@/types/api";

interface Props {
  widget: Widget;
  payload?: WidgetData;
}

function ErrorCard({ message }: { message: string }) {
  return (
    <Card className="h-full">
      <CardContent className="flex h-full items-center justify-center p-4 text-center">
        <p className="text-xs text-destructive">{message}</p>
      </CardContent>
    </Card>
  );
}

export function WidgetRenderer({ widget, payload }: Props) {
  if (payload?.error) {
    return <ErrorCard message={payload.error} />;
  }
  // The renderer is positional: `payload` is whatever the server
  // resolved for THIS widget's slot. `data` is typed `unknown` because
  // the union of payload shapes is too big to express cleanly; each
  // widget component casts to the shape it knows via the cast inside
  // the switch arm.
  const data = (payload?.data ?? null) as never;
  switch (widget.type) {
    case "kpi":
      return <KpiWidget widget={widget} data={data} />;
    case "severity_donut":
      return <SeverityDonutWidget data={data} />;
    case "state_donut":
      return <StateDonutWidget data={data} />;
    case "host_status_donut":
      return <HostStatusWidget data={data} />;
    case "top_rules":
      return <TopRulesWidget data={data} />;
    case "timeline_24h":
      return <Timeline24hWidget data={data} />;
    case "hosts_table":
      return <HostsTableWidget data={data} />;
    case "incidents_table":
      return <IncidentsTableWidget data={data} />;
    default:
      return <ErrorCard message="Unknown widget type." />;
  }
}
