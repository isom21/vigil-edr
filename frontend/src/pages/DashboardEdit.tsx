/**
 * Dashboard editor (Phase 3 #3.4).
 *
 * Drag-and-drop grid powered by react-grid-layout. The widget
 * palette in the side panel adds new widgets at the bottom of the
 * grid; the operator can drag/resize them, edit per-widget options,
 * and persist via the Save button. The save is a `PUT` with the
 * complete `widgets_json` array — the editor doesn't track partial
 * diffs.
 */
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { Save, Trash2 } from "lucide-react";
// `react-grid-layout` ships ESM + CSS as separate paths; keep the
// imports narrow so the bundler tree-shakes the rest.
import GridLayout from "react-grid-layout";

import { ApiError } from "@/api/client";
import { dashboardsApi } from "@/api/dashboards";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/PageHeader";
import { WidgetRenderer } from "@/components/widgets/WidgetRenderer";
import type { KpiQuery, Widget, WidgetData, WidgetType } from "@/types/api";

import "react-grid-layout/css/styles.css";

const COLUMNS = 12;
const ROW_HEIGHT = 80;

interface PaletteEntry {
  type: WidgetType;
  label: string;
  defaultW: number;
  defaultH: number;
  build: () => Widget;
}

const KPI_QUERIES: { value: KpiQuery; label: string }[] = [
  { value: "alerts_open", label: "Alerts open" },
  { value: "alerts_today", label: "Alerts today" },
  { value: "hosts_online", label: "Hosts online" },
  { value: "hosts_total", label: "Hosts total" },
  { value: "jobs_failed_24h", label: "Jobs failed (24h)" },
  { value: "avg_mttr_hours", label: "Avg MTTR" },
];

const PALETTE: PaletteEntry[] = [
  {
    type: "kpi",
    label: "KPI tile",
    defaultW: 3,
    defaultH: 2,
    build: () => ({
      type: "kpi",
      title: "Open alerts",
      query: "alerts_open",
      position: { x: 0, y: 0, w: 3, h: 2 },
    }),
  },
  {
    type: "severity_donut",
    label: "Severity donut",
    defaultW: 4,
    defaultH: 4,
    build: () => ({
      type: "severity_donut",
      position: { x: 0, y: 0, w: 4, h: 4 },
    }),
  },
  {
    type: "state_donut",
    label: "Alert state donut",
    defaultW: 4,
    defaultH: 4,
    build: () => ({ type: "state_donut", position: { x: 0, y: 0, w: 4, h: 4 } }),
  },
  {
    type: "host_status_donut",
    label: "Host status donut",
    defaultW: 4,
    defaultH: 4,
    build: () => ({
      type: "host_status_donut",
      position: { x: 0, y: 0, w: 4, h: 4 },
    }),
  },
  {
    type: "top_rules",
    label: "Top firing rules",
    defaultW: 4,
    defaultH: 4,
    build: () => ({
      type: "top_rules",
      limit: 10,
      position: { x: 0, y: 0, w: 4, h: 4 },
    }),
  },
  {
    type: "timeline_24h",
    label: "24h timeline",
    defaultW: 12,
    defaultH: 3,
    build: () => ({ type: "timeline_24h", position: { x: 0, y: 0, w: 12, h: 3 } }),
  },
  {
    type: "hosts_table",
    label: "Hosts table",
    defaultW: 6,
    defaultH: 5,
    build: () => ({
      type: "hosts_table",
      limit: 10,
      position: { x: 0, y: 0, w: 6, h: 5 },
    }),
  },
  {
    type: "incidents_table",
    label: "Incidents table",
    defaultW: 6,
    defaultH: 5,
    build: () => ({
      type: "incidents_table",
      limit: 10,
      position: { x: 0, y: 0, w: 6, h: 5 },
    }),
  },
];

function findFreeY(widgets: Widget[]): number {
  if (widgets.length === 0) return 0;
  return Math.max(...widgets.map((w) => w.position.y + w.position.h));
}

export function DashboardEdit() {
  const params = useParams();
  const id = params.id ?? "";
  const navigate = useNavigate();
  const qc = useQueryClient();

  const dashboard = useQuery({
    queryKey: ["dashboard", id],
    queryFn: () => dashboardsApi.get(id),
    enabled: !!id,
  });

  // Initial preview-data fetch — re-uses the same `/data` resolver
  // the public dashboard hits so the editor previews look identical
  // to the rendered overview page.
  const dataQuery = useQuery<WidgetData[]>({
    queryKey: ["dashboard-data", id],
    queryFn: () => dashboardsApi.data(id),
    enabled: !!id,
  });

  const [widgets, setWidgets] = useState<Widget[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [shared, setShared] = useState(false);
  const [isDefault, setIsDefault] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (dashboard.data) {
      setWidgets(dashboard.data.widgets_json);
      setName(dashboard.data.name);
      setDescription(dashboard.data.description ?? "");
      setShared(dashboard.data.shared);
      setIsDefault(dashboard.data.is_default);
    }
  }, [dashboard.data]);

  const layout = useMemo(
    () =>
      widgets.map((w, i) => ({
        i: String(i),
        x: w.position.x,
        y: w.position.y,
        w: w.position.w,
        h: w.position.h,
      })),
    [widgets],
  );

  const save = useMutation({
    mutationFn: () =>
      dashboardsApi.update(id, {
        name,
        description: description || null,
        shared,
        is_default: isDefault,
        widgets_json: widgets,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dashboards"] });
      qc.invalidateQueries({ queryKey: ["dashboard", id] });
      qc.invalidateQueries({ queryKey: ["dashboard", "default"] });
      navigate("/dashboards");
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  function addWidget(entry: PaletteEntry) {
    const w = entry.build();
    w.position = {
      x: 0,
      y: findFreeY(widgets),
      w: entry.defaultW,
      h: entry.defaultH,
    };
    setWidgets((ws) => [...ws, w]);
  }

  function removeWidget(idx: number) {
    setWidgets((ws) => ws.filter((_, i) => i !== idx));
  }

  function updateWidget(idx: number, patch: Partial<Widget>) {
    setWidgets((ws) => ws.map((w, i) => (i === idx ? ({ ...w, ...patch } as Widget) : w)));
  }

  function onLayoutChange(next: { i: string; x: number; y: number; w: number; h: number }[]) {
    setWidgets((ws) =>
      ws.map((w, i) => {
        const l = next.find((n) => n.i === String(i));
        if (!l) return w;
        return { ...w, position: { x: l.x, y: l.y, w: l.w, h: l.h } };
      }),
    );
  }

  if (!id) return null;

  return (
    <>
      <PageHeader
        title={name || "Dashboard"}
        description="Drag widgets to rearrange, resize from the bottom-right corner."
        actions={
          <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending}>
            <Save className="mr-2 h-4 w-4" aria-hidden="true" />
            Save
          </Button>
        }
      />
      <div className="grid grid-cols-[1fr_18rem] gap-4 p-6">
        <div className="space-y-4">
          {error && (
            <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {error}
            </p>
          )}
          <Card>
            <CardContent className="p-4">
              <GridLayout
                className="layout"
                layout={layout}
                cols={COLUMNS}
                rowHeight={ROW_HEIGHT}
                width={900}
                margin={[10, 10]}
                isDraggable
                isResizable
                onLayoutChange={onLayoutChange}
                draggableCancel=".widget-actions"
              >
                {widgets.map((w, i) => (
                  <div key={String(i)} className="relative">
                    <div className="widget-actions absolute right-1 top-1 z-10">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => removeWidget(i)}
                        title="Remove widget"
                      >
                        <Trash2 className="h-3 w-3" aria-hidden="true" />
                      </Button>
                    </div>
                    <WidgetRenderer widget={w} payload={dataQuery.data?.[i]} />
                  </div>
                ))}
              </GridLayout>
              {widgets.length === 0 && (
                <p className="py-12 text-center text-sm text-muted-foreground">
                  Empty dashboard — add widgets from the palette to the right.
                </p>
              )}
            </CardContent>
          </Card>
        </div>
        <aside className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Properties</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 p-4">
              <div className="space-y-1">
                <Label htmlFor="dash-name">Name</Label>
                <Input id="dash-name" value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="dash-desc">Description</Label>
                <Textarea
                  id="dash-desc"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                />
              </div>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={shared} onCheckedChange={(c) => setShared(!!c)} />
                Share with team
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={isDefault} onCheckedChange={(c) => setIsDefault(!!c)} />
                Set as my default
              </label>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Widgets</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1 p-2">
              {PALETTE.map((entry) => (
                <Button
                  key={entry.type}
                  size="sm"
                  variant="ghost"
                  className="w-full justify-start"
                  onClick={() => addWidget(entry)}
                >
                  {entry.label}
                </Button>
              ))}
            </CardContent>
          </Card>
          <Separator />
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Per-widget options</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 p-4">
              {widgets.length === 0 && (
                <p className="text-xs text-muted-foreground">Add a widget to edit its options.</p>
              )}
              {widgets.map((w, i) => (
                <WidgetOptionsEditor
                  key={i}
                  widget={w}
                  onChange={(patch) => updateWidget(i, patch)}
                />
              ))}
            </CardContent>
          </Card>
        </aside>
      </div>
    </>
  );
}

interface OptionsProps {
  widget: Widget;
  onChange: (patch: Partial<Widget>) => void;
}

function WidgetOptionsEditor({ widget, onChange }: OptionsProps) {
  const summary = (() => {
    switch (widget.type) {
      case "kpi":
        return `KPI — ${widget.title}`;
      case "top_rules":
      case "hosts_table":
      case "incidents_table":
        return `${widget.type} (limit ${widget.limit})`;
      default:
        return widget.type;
    }
  })();

  if (widget.type === "kpi") {
    return (
      <div className="space-y-1 rounded-md border p-2">
        <p className="text-xs font-medium text-muted-foreground">{summary}</p>
        <Input
          value={widget.title}
          onChange={(e) => onChange({ ...widget, title: e.target.value } as Widget)}
          placeholder="Title"
        />
        <select
          className="w-full rounded-md border bg-background px-2 py-1 text-sm"
          value={widget.query}
          onChange={(e) => onChange({ ...widget, query: e.target.value as KpiQuery } as Widget)}
        >
          {KPI_QUERIES.map((q) => (
            <option key={q.value} value={q.value}>
              {q.label}
            </option>
          ))}
        </select>
      </div>
    );
  }

  if (
    widget.type === "top_rules" ||
    widget.type === "hosts_table" ||
    widget.type === "incidents_table"
  ) {
    return (
      <div className="space-y-1 rounded-md border p-2">
        <p className="text-xs font-medium text-muted-foreground">{summary}</p>
        <Input
          type="number"
          min={1}
          max={100}
          value={widget.limit}
          onChange={(e) => {
            const n = Number(e.target.value);
            if (!Number.isFinite(n) || n < 1) return;
            onChange({ ...widget, limit: n } as Widget);
          }}
        />
      </div>
    );
  }

  return <div className="rounded-md border p-2 text-xs text-muted-foreground">{summary}</div>;
}
