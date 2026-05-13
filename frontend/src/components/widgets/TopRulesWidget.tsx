/**
 * Top-firing-rules bar chart (Phase 3 #3.4). Mirrors the bar chart
 * from the hardcoded Dashboard.tsx.
 */
import { BarChart, ChartCard } from "@/components/charts";

interface Bucket {
  key: string;
  count: number;
}

interface Props {
  data: Bucket[] | null;
}

export function TopRulesWidget({ data }: Props) {
  return (
    <ChartCard title="Top firing rules">
      <BarChart data={(data ?? []).map((b) => ({ key: b.key, count: b.count }))} />
    </ChartCard>
  );
}
