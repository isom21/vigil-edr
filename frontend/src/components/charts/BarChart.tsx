import { cn } from "@/lib/utils";

export interface Bar {
  key: string;
  label?: string;
  count: number;
  color?: string;
}

interface Props {
  data: Bar[];
  className?: string;
  onBarClick?: (b: Bar) => void;
  activeKey?: string | null;
  /** Truncate the label to N chars in the chart. */
  labelTruncate?: number;
}

export function BarChart({ data, className, onBarClick, activeKey, labelTruncate = 24 }: Props) {
  const max = Math.max(1, ...data.map((d) => d.count));
  return (
    <ul className={cn("space-y-1.5 text-xs", className)}>
      {data.length === 0 && <li className="text-muted-foreground">No data.</li>}
      {data.map((d) => {
        const pct = (d.count / max) * 100;
        const label = d.label ?? d.key;
        const truncated =
          label.length > labelTruncate ? label.slice(0, labelTruncate) + "…" : label;
        return (
          <li
            key={d.key}
            className={cn(
              "group grid grid-cols-[8rem,1fr,2.5rem] items-center gap-2",
              onBarClick && "cursor-pointer",
              activeKey && activeKey !== d.key && "opacity-60",
            )}
            onClick={() => onBarClick?.(d)}
            title={`${label}: ${d.count}`}
          >
            <span className="truncate text-muted-foreground group-hover:text-foreground">
              {truncated}
            </span>
            <span className="relative h-2 rounded-full bg-secondary/40">
              <span
                className="absolute inset-y-0 left-0 rounded-full transition-all"
                style={{
                  width: `${pct}%`,
                  backgroundColor: d.color ?? "hsl(var(--primary))",
                }}
              />
            </span>
            <span className="text-right font-medium">{d.count}</span>
          </li>
        );
      })}
    </ul>
  );
}
