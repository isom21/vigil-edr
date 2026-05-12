/**
 * M22.b: live alert stream + toast notifier.
 *
 * Mounts a single EventSource against `/api/alerts/stream` for the
 * lifetime of the layout. Each incoming `alert` event invalidates
 * the alerts list query (so any open Alerts page refreshes) and
 * pops a transient toast for high+critical severities so the
 * operator sees them even when looking at a different page.
 *
 * EventSource can't set Authorization headers, so the access token
 * rides along in `?access_token=…` — the backend's
 * current_actor_stream dep honours either form.
 */
/* global EventSource, MessageEvent, EventListener */
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, X } from "lucide-react";
import { tokenStore } from "@/api/tokens";
import { cn } from "@/lib/utils";
import type { Alert } from "@/types/api";

interface Toast {
  id: string;
  alertId: string;
  summary: string;
  hostname: string | null;
  severity: Alert["severity"];
  ts: number;
}

const TOAST_MAX = 5;
const TOAST_TTL_MS = 15_000;

// Reconnect backoff: 2s → 30s, doubling on each failure. Reset to 2s
// on a successful onopen so a brief blip doesn't leave us cooling
// down for the next failure.
const RECONNECT_MIN_MS = 2_000;
const RECONNECT_MAX_MS = 30_000;

export function AlertStreamToasts() {
  const qc = useQueryClient();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const access = tokenStore.getAccessToken();
    if (!access) return;
    const url = `/api/alerts/stream?access_token=${encodeURIComponent(access)}`;

    let cancelled = false;
    let backoffMs = RECONNECT_MIN_MS;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    const onAlert = (msg: MessageEvent) => {
      let alert: Alert | null = null;
      try {
        alert = JSON.parse(msg.data);
      } catch {
        return;
      }
      if (!alert) return;
      // Push the new alert into any active queries so the table
      // reflects the row without waiting for a refetch.
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["alert-stats"] });
      if (alert.severity === "high" || alert.severity === "critical") {
        setToasts((prev) => {
          const next = [
            {
              id: `${alert!.id}-${Date.now()}`,
              alertId: alert!.id,
              summary: alert!.summary,
              hostname: alert!.host_hostname ?? null,
              severity: alert!.severity,
              ts: Date.now(),
            },
            ...prev,
          ];
          return next.slice(0, TOAST_MAX);
        });
      }
    };

    const connect = () => {
      if (cancelled) return;
      const es = new EventSource(url);
      esRef.current = es;
      es.addEventListener("alert", onAlert as EventListener);
      // `ready` and `ping` are harmless filler — ignore them.
      es.onopen = () => {
        backoffMs = RECONNECT_MIN_MS;
      };
      es.onerror = () => {
        // EventSource will reconnect on its own for clean network
        // hiccups, but if the server returned a non-2xx (e.g. 401
        // after the access token expired) it lands in a permanent
        // CLOSED state. Close + reschedule ourselves so we recover
        // either way.
        es.close();
        esRef.current = null;
        if (cancelled) return;
        retryTimer = setTimeout(connect, backoffMs);
        backoffMs = Math.min(backoffMs * 2, RECONNECT_MAX_MS);
      };
    };
    connect();

    return () => {
      cancelled = true;
      if (retryTimer !== null) clearTimeout(retryTimer);
      esRef.current?.close();
      esRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Expire toasts after TTL.
  useEffect(() => {
    if (toasts.length === 0) return;
    const id = setInterval(() => {
      const now = Date.now();
      setToasts((prev) => prev.filter((t) => now - t.ts < TOAST_TTL_MS));
    }, 1000);
    return () => clearInterval(id);
  }, [toasts.length]);

  if (toasts.length === 0) return null;
  return (
    <div
      // The outer region is just a landmark; each toast carries its
      // own role="alert"/aria-live="assertive" below so a CRITICAL or
      // HIGH severity reaches a screen reader immediately rather than
      // queueing behind whatever the user is reading.
      aria-label="New high-severity alerts"
      className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col-reverse gap-2"
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          role="alert"
          aria-live="assertive"
          className={cn(
            "pointer-events-auto flex items-start gap-2 rounded-md border bg-card p-3 shadow-lg",
            t.severity === "critical" ? "border-sev-critical/40" : "border-sev-high/40",
          )}
        >
          <AlertTriangle
            className={cn(
              "mt-0.5 h-4 w-4 shrink-0",
              t.severity === "critical" ? "text-sev-critical" : "text-sev-high",
            )}
          />
          <div className="min-w-0 flex-1">
            <Link
              to={`/alerts/${t.alertId}`}
              className="block truncate text-sm font-medium hover:underline"
              onClick={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
            >
              {t.summary}
            </Link>
            <div className="text-xs text-muted-foreground">
              {t.severity} · {t.hostname ?? "unknown host"}
            </div>
          </div>
          <button
            type="button"
            onClick={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
            className="rounded-full p-0.5 text-muted-foreground hover:bg-secondary/70 hover:text-foreground"
            aria-label="Dismiss"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}
