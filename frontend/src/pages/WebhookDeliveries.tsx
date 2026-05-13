/**
 * Per-subscription delivery history (Phase 3 #3.7).
 *
 * Paginated table of `webhook_delivery` rows so an operator can debug
 * receiver-side rejects (signature mismatch, 4xx, transient outages)
 * without having to dig through the manager logs.
 */
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";

import { webhooksApi } from "@/api/webhooks";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { WebhookDelivery } from "@/types/api";

const PAGE_SIZE = 50;

const STATUS_CLASS: Record<WebhookDelivery["status"], string> = {
  pending: "text-amber-500",
  delivered: "text-emerald-500",
  failed: "text-destructive",
  disabled: "text-muted-foreground",
};

function formatTimestamp(ts: string | null): string {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export function WebhookDeliveries() {
  const { id = "" } = useParams<{ id: string }>();
  const [page, setPage] = useState(0);

  const sub = useQuery({
    queryKey: ["webhooks", id],
    queryFn: () => webhooksApi.get(id),
    enabled: id.length > 0,
  });

  const deliveries = useQuery({
    queryKey: ["webhooks", id, "deliveries", page],
    queryFn: () => webhooksApi.deliveries(id, PAGE_SIZE, page * PAGE_SIZE),
    enabled: id.length > 0,
    refetchInterval: 10_000,
  });

  const total = deliveries.data?.total ?? 0;
  const lastPage = total === 0 ? 0 : Math.ceil(total / PAGE_SIZE) - 1;

  return (
    <>
      <PageHeader
        title={sub.data ? `Deliveries · ${sub.data.name}` : "Deliveries"}
        description={
          sub.data ? <span className="font-mono text-xs">{sub.data.url}</span> : "Loading…"
        }
        actions={
          <Button asChild size="sm" variant="secondary">
            <Link to="/webhooks">
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
              Back
            </Link>
          </Button>
        }
      />
      <div className="space-y-4 px-8 py-6">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">
              {total} {total === 1 ? "delivery" : "deliveries"}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {deliveries.isLoading && (
              <p className="text-sm text-muted-foreground">Loading deliveries…</p>
            )}
            {!deliveries.isLoading && (deliveries.data?.items.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground">
                No deliveries recorded yet. Fire a test from the subscription page or wait for the
                first matching event.
              </p>
            )}
            <ul className="divide-y divide-border">
              {deliveries.data?.items.map((d) => (
                <li key={d.id} className="py-3 text-sm">
                  <div className="flex items-center gap-3">
                    <span
                      className={`text-[10px] uppercase tracking-wider ${STATUS_CLASS[d.status]}`}
                    >
                      {d.status}
                    </span>
                    <span className="font-mono text-xs">{d.event_type}</span>
                    <span className="text-xs text-muted-foreground">
                      HTTP {d.response_status ?? "—"} · {d.attempts} attempt
                      {d.attempts === 1 ? "" : "s"}
                    </span>
                    <span className="ml-auto text-xs text-muted-foreground">
                      {formatTimestamp(d.delivered_at ?? d.created_at)}
                    </span>
                  </div>
                  {d.response_body_truncated && (
                    <pre className="mt-2 max-h-32 overflow-auto rounded-sm bg-secondary px-2 py-1 font-mono text-[11px] text-muted-foreground">
                      {d.response_body_truncated}
                    </pre>
                  )}
                </li>
              ))}
            </ul>
            {total > PAGE_SIZE && (
              <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
                <span>
                  Page {page + 1} of {lastPage + 1}
                </span>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page === 0}
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                  >
                    Prev
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page >= lastPage}
                    onClick={() => setPage((p) => Math.min(lastPage, p + 1))}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
