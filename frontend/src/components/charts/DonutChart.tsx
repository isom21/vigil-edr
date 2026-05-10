import { useMemo } from "react";
import { cn } from "@/lib/utils";

export interface DonutSlice {
  key: string;
  label?: string;
  count: number;
  color: string;
}

interface Props {
  data: DonutSlice[];
  /** Diameter in px. */
  size?: number;
  /** Hole as a fraction of the radius. */
  thickness?: number;
  /** Center label override. Defaults to total count. */
  centerLabel?: string;
  centerSubLabel?: string;
  className?: string;
  onSliceClick?: (slice: DonutSlice) => void;
  activeKey?: string | null;
}

const TWO_PI = Math.PI * 2;

function polar(cx: number, cy: number, r: number, angle: number): [number, number] {
  return [cx + r * Math.sin(angle), cy - r * Math.cos(angle)];
}

function arcPath(cx: number, cy: number, rOuter: number, rInner: number, a0: number, a1: number) {
  const [x0o, y0o] = polar(cx, cy, rOuter, a0);
  const [x1o, y1o] = polar(cx, cy, rOuter, a1);
  const [x0i, y0i] = polar(cx, cy, rInner, a1);
  const [x1i, y1i] = polar(cx, cy, rInner, a0);
  const large = a1 - a0 > Math.PI ? 1 : 0;
  return [
    `M ${x0o} ${y0o}`,
    `A ${rOuter} ${rOuter} 0 ${large} 1 ${x1o} ${y1o}`,
    `L ${x0i} ${y0i}`,
    `A ${rInner} ${rInner} 0 ${large} 0 ${x1i} ${y1i}`,
    "Z",
  ].join(" ");
}

export function DonutChart({
  data,
  size = 140,
  thickness = 0.6,
  centerLabel,
  centerSubLabel,
  className,
  onSliceClick,
  activeKey,
}: Props) {
  const total = useMemo(() => data.reduce((s, d) => s + d.count, 0), [data]);

  const slices = useMemo(() => {
    if (total === 0) return [];
    const cx = size / 2;
    const cy = size / 2;
    const rOuter = size / 2 - 1;
    const rInner = rOuter * thickness;
    let a = 0;
    return data.map((d) => {
      const sweep = (d.count / total) * TWO_PI;
      // Avoid 0-width arcs that render as full circles when sweep===0.
      const safeSweep = Math.max(sweep, 0.0001);
      const path = arcPath(cx, cy, rOuter, rInner, a, a + safeSweep);
      a += sweep;
      return { ...d, path };
    });
  }, [data, total, size, thickness]);

  return (
    <div className={cn("flex items-center gap-4", className)}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {total === 0 ? (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={size / 2 - 1}
            fill="none"
            stroke="hsl(var(--border))"
            strokeWidth={size * (1 - thickness) * 0.5}
          />
        ) : (
          slices.map((s) => (
            <path
              key={s.key}
              d={s.path}
              fill={s.color}
              opacity={activeKey && activeKey !== s.key ? 0.35 : 1}
              className={cn(
                "transition-opacity",
                onSliceClick && "cursor-pointer hover:opacity-80",
              )}
              onClick={() => onSliceClick?.(s)}
            >
              <title>
                {s.label ?? s.key}: {s.count}
              </title>
            </path>
          ))
        )}
        <text
          x={size / 2}
          y={size / 2 - 2}
          textAnchor="middle"
          dominantBaseline="middle"
          className="fill-foreground text-lg font-semibold"
          style={{ fontSize: size * 0.16 }}
        >
          {centerLabel ?? total.toLocaleString()}
        </text>
        {(centerSubLabel || centerLabel === undefined) && (
          <text
            x={size / 2}
            y={size / 2 + size * 0.12}
            textAnchor="middle"
            dominantBaseline="middle"
            className="fill-muted-foreground"
            style={{ fontSize: size * 0.08 }}
          >
            {centerSubLabel ?? "total"}
          </text>
        )}
      </svg>
      <ul className="space-y-1 text-xs">
        {data.map((d) => (
          <li
            key={d.key}
            className={cn(
              "flex items-center gap-2",
              onSliceClick && "cursor-pointer hover:text-foreground",
              activeKey && activeKey !== d.key && "opacity-60",
            )}
            onClick={() => onSliceClick?.(d)}
          >
            <span className="h-2 w-2 shrink-0 rounded-sm" style={{ backgroundColor: d.color }} />
            <span className="text-muted-foreground">{d.label ?? d.key}</span>
            <span className="ml-auto font-medium">{d.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
