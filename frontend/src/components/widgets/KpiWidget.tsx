/**
 * KPI widget (Phase 3 #3.4).
 *
 * Single big number + label. The colour intentionally stays neutral
 * (foreground) because the KPI's *meaning* — open alerts, failed
 * jobs, MTTR — is encoded in the title rather than in semantic
 * styling. Operators who want a coloured pill can wrap the dashboard
 * grid in a coloured card on the page; this widget stays generic.
 */
import { Card, CardContent } from "@/components/ui/card";
import type { KpiWidget as KpiWidgetType } from "@/types/api";

interface KpiData {
  value: number;
  unit: string | null;
}

interface Props {
  widget: KpiWidgetType;
  data: KpiData | null;
}

export function KpiWidget({ widget, data }: Props) {
  return (
    <Card className="h-full">
      <CardContent className="flex h-full flex-col justify-between p-4">
        <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          {widget.title}
        </div>
        <div className="text-4xl font-semibold tabular-nums">
          {data ? data.value : "—"}
          {data?.unit && (
            <span className="ml-1 text-base font-normal text-muted-foreground">{data.unit}</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
