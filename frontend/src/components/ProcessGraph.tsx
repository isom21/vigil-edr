/**
 * Phase 2 #2.6: cross-process correlation graph viewer.
 *
 * Renders the durable Postgres-backed process chain for an alert as a
 * plain SVG tree — react-flow isn't installed, and the graph store
 * only persists a linear ancestry plus first-level descendants, so a
 * hand-rolled SVG tree is overkill-proof.
 *
 * Each node shows the pid + the basename of `exec_path`. The full
 * command line shows up on hover via `<title>` so the analyst can
 * spot suspicious arguments without expanding a panel.
 */
import { useQuery } from "@tanstack/react-query";
import { processChainApi } from "@/api/process_chain";
import { ApiError } from "@/api/client";
import type { ProcessChainNodePG, ProcessChainResponse } from "@/types/api";

interface Props {
  alertId: string;
}

const NODE_WIDTH = 220;
const NODE_HEIGHT = 50;
const VERTICAL_GAP = 24;
const HORIZONTAL_GAP = 24;
const TOP_PADDING = 8;
const SIDE_PADDING = 12;

function basename(path: string | null): string | null {
  if (!path) return null;
  const normalised = path.replace(/\\/g, "/");
  const lastSlash = normalised.lastIndexOf("/");
  return lastSlash === -1 ? normalised : normalised.slice(lastSlash + 1);
}

interface LaidOutNode {
  node: ProcessChainNodePG;
  x: number;
  y: number;
  highlight: boolean;
}

interface LaidOutEdge {
  fromX: number;
  fromY: number;
  toX: number;
  toY: number;
}

function layout(data: ProcessChainResponse): {
  nodes: LaidOutNode[];
  edges: LaidOutEdge[];
  width: number;
  height: number;
} {
  // Linear vertical layout: ancestors stack top-to-bottom (root → seed),
  // descendants spread to the right of the seed pid at the bottom row.
  const ancestors = data.ancestors;
  const seedPid = data.pid;
  const descendants = data.descendants;

  const ancestorRows = ancestors.length;
  const descendantsRow = descendants.length > 0 ? 1 : 0;

  const cx = SIDE_PADDING + NODE_WIDTH / 2;
  const nodes: LaidOutNode[] = [];
  const edges: LaidOutEdge[] = [];

  ancestors.forEach((n, i) => {
    const y = TOP_PADDING + i * (NODE_HEIGHT + VERTICAL_GAP);
    nodes.push({
      node: n,
      x: cx - NODE_WIDTH / 2,
      y,
      highlight: n.pid === seedPid,
    });
    if (i > 0) {
      const prevY = TOP_PADDING + (i - 1) * (NODE_HEIGHT + VERTICAL_GAP);
      edges.push({
        fromX: cx,
        fromY: prevY + NODE_HEIGHT,
        toX: cx,
        toY: y,
      });
    }
  });

  // Descendants live one row below the deepest ancestor (the seed pid).
  const descRowY = TOP_PADDING + ancestorRows * (NODE_HEIGHT + VERTICAL_GAP);
  descendants.forEach((n, i) => {
    const x = SIDE_PADDING + i * (NODE_WIDTH + HORIZONTAL_GAP);
    nodes.push({
      node: n,
      x,
      y: descRowY,
      highlight: false,
    });
    if (ancestorRows > 0) {
      const seedBottomY =
        TOP_PADDING + (ancestorRows - 1) * (NODE_HEIGHT + VERTICAL_GAP) + NODE_HEIGHT;
      edges.push({
        fromX: cx,
        fromY: seedBottomY,
        toX: x + NODE_WIDTH / 2,
        toY: descRowY,
      });
    }
  });

  const descendantsWidth =
    descendants.length > 0
      ? descendants.length * NODE_WIDTH + (descendants.length - 1) * HORIZONTAL_GAP
      : NODE_WIDTH;
  const width = SIDE_PADDING * 2 + Math.max(NODE_WIDTH, descendantsWidth);
  const ancestorsHeight = ancestorRows * NODE_HEIGHT + Math.max(0, ancestorRows - 1) * VERTICAL_GAP;
  const height =
    TOP_PADDING * 2 + ancestorsHeight + (descendantsRow > 0 ? VERTICAL_GAP + NODE_HEIGHT : 0);
  return { nodes, edges, width, height };
}

export function ProcessGraph({ alertId }: Props) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["alert-process-chain", alertId],
    queryFn: () => processChainApi.forAlert(alertId),
    // The backend issues a 400 when the alert has no triggering pid in
    // details — treat that as "graph unavailable" rather than an error
    // so the alert detail page still renders the existing OS-derived
    // chain alongside.
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 400 || err.status === 404)) return false;
      return failureCount < 2;
    },
  });

  if (isLoading) {
    return (
      <div className="rounded-md border border-dashed border-border/60 p-4 text-xs text-muted-foreground">
        Loading process graph…
      </div>
    );
  }
  if (isError) {
    const friendly =
      error instanceof ApiError && (error.status === 400 || error.status === 404)
        ? "No durable process graph is available for this alert yet."
        : error instanceof Error
          ? error.message
          : "Failed to load.";
    return (
      <div className="rounded-md border border-dashed border-border/60 p-4 text-xs text-muted-foreground">
        {friendly}
      </div>
    );
  }
  if (!data || (data.ancestors.length === 0 && data.descendants.length === 0)) {
    return (
      <div className="rounded-md border border-dashed border-border/60 p-4 text-xs text-muted-foreground">
        No durable process-chain rows are recorded for this alert's triggering pid.
      </div>
    );
  }

  const { nodes, edges, width, height } = layout(data);

  return (
    <div className="overflow-x-auto rounded-md border border-border/60 bg-card/40 p-2">
      <svg
        role="img"
        aria-label="Process chain graph"
        width={width}
        height={height}
        className="max-w-full"
      >
        {edges.map((e, i) => (
          <line
            key={`e-${i}`}
            x1={e.fromX}
            y1={e.fromY}
            x2={e.toX}
            y2={e.toY}
            stroke="currentColor"
            strokeOpacity={0.25}
            strokeWidth={1}
          />
        ))}
        {nodes.map((n) => {
          const exe = basename(n.node.exec_path);
          const title = n.node.command_line ?? n.node.exec_path ?? `pid ${n.node.pid}`;
          return (
            <g key={n.node.id} transform={`translate(${n.x}, ${n.y})`}>
              <title>{title}</title>
              <rect
                width={NODE_WIDTH}
                height={NODE_HEIGHT}
                rx={6}
                ry={6}
                className={
                  n.highlight ? "fill-sev-medium/10 stroke-sev-medium" : "fill-card stroke-border"
                }
                strokeWidth={1}
              />
              <text x={10} y={20} className="fill-foreground font-mono text-[11px]">
                pid {n.node.pid}
              </text>
              <text x={10} y={38} className="fill-muted-foreground font-mono text-[11px]">
                {exe ?? "(unknown)"}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
