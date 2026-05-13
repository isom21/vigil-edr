/**
 * Operator-authored dashboard view (Phase 3 #3.4).
 *
 * Reads `GET /api/dashboards/default` to discover the caller's
 * default layout, then renders each widget through `WidgetRenderer`.
 * The page no longer hard-codes the chart strip — operators author
 * their own layouts on `/dashboards/:id`. The first time a user
 * lands here the server auto-creates a default that mirrors the
 * historical hardcoded layout so the page never renders empty.
 *
 * Admin+ get an "Edit dashboard" button that links to the editor.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Pencil } from "lucide-react";

import { dashboardsApi } from "@/api/dashboards";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { WidgetRenderer } from "@/components/widgets/WidgetRenderer";
import { useAuth } from "@/hooks/useAuth";

const ROW_HEIGHT = 96;
const COLUMNS = 12;

export function Dashboard() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const dashboard = useQuery({
    queryKey: ["dashboard", "default"],
    queryFn: () => dashboardsApi.getDefault(),
  });

  const data = useQuery({
    queryKey: ["dashboard-data", dashboard.data?.id],
    queryFn: () => dashboardsApi.data(dashboard.data!.id),
    enabled: !!dashboard.data?.id,
    refetchInterval: 30_000,
  });

  return (
    <>
      <PageHeader
        title={dashboard.data?.name ?? "Dashboard"}
        description="Live overview — counts refresh every 30s."
        actions={
          isAdmin && dashboard.data ? (
            <Button asChild variant="outline" size="sm">
              <Link to={`/dashboards/${dashboard.data.id}`}>
                <Pencil className="mr-2 h-4 w-4" aria-hidden="true" />
                Edit dashboard
              </Link>
            </Button>
          ) : null
        }
      />
      <div className="space-y-6 px-8 py-6">
        {dashboard.isLoading && (
          <Card>
            <CardContent className="p-4 text-sm text-muted-foreground">
              Loading dashboard…
            </CardContent>
          </Card>
        )}
        {dashboard.data && (
          <div
            className="relative grid gap-3"
            style={{
              gridTemplateColumns: `repeat(${COLUMNS}, minmax(0, 1fr))`,
            }}
          >
            {dashboard.data.widgets_json.map((w, i) => (
              <div
                key={i}
                style={{
                  gridColumnStart: w.position.x + 1,
                  gridColumnEnd: `span ${Math.min(w.position.w, COLUMNS)}`,
                  gridRowStart: w.position.y + 1,
                  gridRowEnd: `span ${w.position.h}`,
                  minHeight: w.position.h * ROW_HEIGHT,
                }}
              >
                <WidgetRenderer widget={w} payload={data.data?.[i]} />
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
