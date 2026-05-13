/**
 * Severity donut (Phase 3 #3.4). Mirrors the donut from the
 * hardcoded Dashboard.tsx so the migration is visually a no-op.
 */
import { ChartCard, DonutChart } from "@/components/charts";
import { SEVERITY_HSL } from "@/lib/severity";
import type { Severity } from "@/types/api";

interface Bucket {
  key: string;
  count: number;
}

interface Props {
  data: Bucket[] | null;
}

const SEVS: { key: Severity; label: string }[] = [
  { key: "critical", label: "critical" },
  { key: "high", label: "high" },
  { key: "medium", label: "medium" },
  { key: "low", label: "low" },
  { key: "info", label: "info" },
];

function pick(buckets: Bucket[] | null, key: string): number {
  return buckets?.find((b) => b.key === key)?.count ?? 0;
}

export function SeverityDonutWidget({ data }: Props) {
  return (
    <ChartCard title="Severity">
      <DonutChart
        data={SEVS.map(({ key, label }) => ({
          key,
          label,
          color: SEVERITY_HSL[key],
          count: pick(data, key),
        }))}
        size={130}
      />
    </ChartCard>
  );
}
