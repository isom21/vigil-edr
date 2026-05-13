/**
 * Alert-state donut (Phase 3 #3.4). Mirrors the donut from the
 * hardcoded Dashboard.tsx.
 */
import { ChartCard, DonutChart } from "@/components/charts";
import { SEVERITY_HSL } from "@/lib/severity";

interface Bucket {
  key: string;
  count: number;
}

interface Props {
  data: Bucket[] | null;
}

function pick(buckets: Bucket[] | null, key: string): number {
  return buckets?.find((b) => b.key === key)?.count ?? 0;
}

export function StateDonutWidget({ data }: Props) {
  return (
    <ChartCard title="Alert state">
      <DonutChart
        data={[
          {
            key: "new",
            label: "new",
            color: SEVERITY_HSL.medium,
            count: pick(data, "new"),
          },
          {
            key: "investigating",
            label: "investigating",
            color: SEVERITY_HSL.low,
            count: pick(data, "investigating"),
          },
          {
            key: "true_positive",
            label: "true positive",
            color: SEVERITY_HSL.critical,
            count: pick(data, "true_positive"),
          },
          {
            key: "false_positive",
            label: "false positive",
            color: "hsl(var(--muted-foreground))",
            count: pick(data, "false_positive"),
          },
        ]}
        size={130}
      />
    </ChartCard>
  );
}
