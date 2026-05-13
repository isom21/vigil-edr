import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { ApiError } from "@/api/client";
import { openTerminalSession } from "@/api/terminal";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";

/**
 * Phase 1 #1.4 — live-response remote shell.
 *
 * Opens a terminal session against the host via `POST
 * /api/hosts/:id/terminal`, then upgrades the WebSocket the response
 * pointed at and pipes bytes through xterm.js.
 *
 * Wire format (JSON):
 *   In  ⇨ manager: { t: "in", d: <base64 stdin> }
 *                 | { t: "resize", cols, rows }
 *                 | { t: "close" }
 *   Out ⇦ manager: { t: "out", d: <base64 stdout/stderr> }
 *                 | { t: "exit", code, reason }
 */
export function HostTerminal() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [status, setStatus] = useState<"connecting" | "connected" | "closed" | "error">(
    "connecting",
  );
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id || !containerRef.current) return;
    let disposed = false;

    const term = new Terminal({
      cursorBlink: true,
      convertEol: false,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      fontSize: 13,
      theme: { background: "#0b0f17", foreground: "#e2e8f0" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const onResizeWindow = () => {
      try {
        fit.fit();
      } catch {
        /* container not laid out yet */
      }
    };
    window.addEventListener("resize", onResizeWindow);

    const sendIfOpen = (payload: object) => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(payload));
      }
    };

    (async () => {
      try {
        const session = await openTerminalSession(id);
        if (disposed) return;
        const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
        const url = `${scheme}//${window.location.host}${session.ws_url}`;
        const ws = new WebSocket(url);
        wsRef.current = ws;

        ws.onopen = () => {
          setStatus("connected");
          // Initial resize so the agent's PTY matches what xterm.js
          // is rendering.
          sendIfOpen({ t: "resize", cols: term.cols, rows: term.rows });
        };
        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data as string) as
              | { t: "out"; d: string }
              | { t: "exit"; code: number; reason: string };
            if (msg.t === "out") {
              const bytes = b64decode(msg.d);
              term.write(bytes);
            } else if (msg.t === "exit") {
              term.writeln("");
              term.writeln(
                `[33m-- session ended (${msg.reason ?? "closed"}, exit=${msg.code}) --[0m`,
              );
              setStatus("closed");
            }
          } catch {
            /* ignore malformed frame */
          }
        };
        ws.onerror = () => {
          setStatus("error");
          setError("WebSocket error");
        };
        ws.onclose = () => {
          if (!disposed) setStatus((s) => (s === "error" ? s : "closed"));
        };

        // Stream stdin to manager.
        term.onData((data) => {
          sendIfOpen({ t: "in", d: b64encode(new TextEncoder().encode(data)) });
        });
        term.onResize(({ cols, rows }) => {
          sendIfOpen({ t: "resize", cols, rows });
        });
      } catch (err) {
        setStatus("error");
        setError(err instanceof ApiError ? err.detail : "failed to open terminal session");
      }
    })();

    return () => {
      disposed = true;
      window.removeEventListener("resize", onResizeWindow);
      try {
        wsRef.current?.send(JSON.stringify({ t: "close" }));
      } catch {
        /* socket may already be closed */
      }
      wsRef.current?.close();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [id]);

  return (
    <>
      <PageHeader
        title="Remote terminal"
        description={`Live response shell · host ${id ?? ""}`}
        actions={
          <Button variant="outline" onClick={() => navigate(-1)}>
            Close
          </Button>
        }
      />
      <div className="flex h-[calc(100vh-9rem)] w-full flex-col px-6 pb-6">
        <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
          <span className={`inline-block h-2 w-2 rounded-full ${statusDot(status)}`} aria-hidden />
          <span>{statusLabel(status)}</span>
          {error && <span className="text-destructive">· {error}</span>}
        </div>
        <div
          ref={containerRef}
          className="flex-1 overflow-hidden rounded-md border border-border bg-[#0b0f17] p-2"
          aria-label="Remote shell"
        />
      </div>
    </>
  );
}

function statusDot(s: "connecting" | "connected" | "closed" | "error") {
  switch (s) {
    case "connecting":
      return "bg-amber-500";
    case "connected":
      return "bg-emerald-500";
    case "closed":
      return "bg-muted-foreground";
    case "error":
      return "bg-destructive";
  }
}

function statusLabel(s: "connecting" | "connected" | "closed" | "error") {
  switch (s) {
    case "connecting":
      return "Connecting…";
    case "connected":
      return "Connected";
    case "closed":
      return "Session ended";
    case "error":
      return "Disconnected";
  }
}

function b64encode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  // urlsafe base64, no padding — matches the server's _b64_encode.
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64decode(s: string): Uint8Array {
  const fixed = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (fixed.length % 4)) % 4);
  const bin = atob(fixed + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
