/**
 * 24h alert timeline (Phase 3 #3.4). Mirrors the sparkline on the
 * hardcoded Dashboard.tsx.
 */
import { Card, CardContent } from "@/components/ui/card";
import { Sparkline } from "@/components/charts";
import { SEVERITY_HSL } from "@/lib/severity";

interface Bucket {
  key: string;
  count: number;
}

interface Props {
  data: Bucket[] | null;
}

export function Timeline24hWidget({ data }: Props) {
  const total = (data ?? []).reduce((s, b) => s + b.count, 0);
  return (
    <Card className="h-full">
      <CardContent className="flex h-full flex-col p-4">
        <div className="mb-2 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Last 24 hours
            </div>
            <div className="text-sm tabular-nums">{total} total alerts</div>
          </div>
        </div>
        <div className="min-h-0 flex-1">
          <Sparkline
            data={(data ?? []).map((b) => ({ ts: b.key, count: b.count }))}
            width={1000}
            height={80}
            color={SEVERITY_HSL.high}
            showAxis
            className="w-full"
          />
        </div>
      </CardContent>
    </Card>
  );
}
