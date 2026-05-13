/**
 * Host-status donut (Phase 3 #3.4). Mirrors the host-status donut
 * from the hardcoded Dashboard.tsx.
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

export function HostStatusWidget({ data }: Props) {
  return (
    <ChartCard title="Host status">
      <DonutChart
        data={[
          {
            key: "online",
            label: "online",
            color: "hsl(143 64% 50%)",
            count: pick(data, "online"),
          },
          {
            key: "offline",
            label: "offline",
            color: "hsl(var(--muted-foreground))",
            count: pick(data, "offline"),
          },
          {
            key: "isolated",
            label: "isolated",
            color: SEVERITY_HSL.critical,
            count: pick(data, "isolated"),
          },
          {
            key: "pending",
            label: "pending",
            color: SEVERITY_HSL.medium,
            count: pick(data, "pending"),
          },
        ]}
        size={130}
      />
    </ChartCard>
  );
}
