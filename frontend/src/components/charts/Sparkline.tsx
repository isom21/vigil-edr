import { useMemo } from "react";
import { cn } from "@/lib/utils";

export interface SparkPoint {
  ts: string;
  count: number;
}

interface Props {
  data: SparkPoint[];
  width?: number;
  height?: number;
  className?: string;
  color?: string;
  /** Render axis labels (first/last bucket) underneath. */
  showAxis?: boolean;
}

export function Sparkline({
  data,
  width = 320,
  height = 60,
  className,
  color = "hsl(var(--primary))",
  showAxis = false,
}: Props) {
  const { path, area, max, total } = useMemo(() => {
    if (data.length === 0) return { path: "", area: "", max: 0, total: 0 };
    const max = Math.max(1, ...data.map((d) => d.count));
    const stepX = data.length > 1 ? width / (data.length - 1) : width;
    const points = data.map((d, i) => {
      const x = i * stepX;
      const y = height - (d.count / max) * (height - 4) - 2;
      return [x, y] as const;
    });
    const path = points
      .map(([x, y], i) => `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`)
      .join(" ");
    const area =
      `M 0 ${height} ` +
      points.map(([x, y]) => `L ${x.toFixed(1)} ${y.toFixed(1)}`).join(" ") +
      ` L ${width} ${height} Z`;
    const total = data.reduce((s, d) => s + d.count, 0);
    return { path, area, max, total };
  }, [data, width, height]);

  const first = data[0]?.ts;
  const last = data[data.length - 1]?.ts;

  return (
    <div className={cn("space-y-1", className)}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="block">
        {data.length > 0 && (
          <>
            <path d={area} fill={color} opacity={0.18} />
            <path d={path} fill="none" stroke={color} strokeWidth={1.5} />
          </>
        )}
      </svg>
      {showAxis && (
        <div className="flex justify-between text-[10px] text-muted-foreground">
          <span>{first ? new Date(first).toLocaleTimeString([], { hour: "2-digit" }) : ""}</span>
          <span>peak: {max}</span>
          <span>total: {total}</span>
          <span>{last ? new Date(last).toLocaleTimeString([], { hour: "2-digit" }) : "now"}</span>
        </div>
      )}
    </div>
  );
}
