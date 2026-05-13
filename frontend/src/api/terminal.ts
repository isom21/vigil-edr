import { api } from "./client";
import type { TerminalSessionToken } from "@/types/api";

/**
 * Phase 1 #1.4 — live-response remote shell.
 *
 * Mint a short-lived session token + session_id for an interactive
 * terminal against `hostId`. The token rides in the WebSocket URL
 * (browsers can't set Authorization on `new WebSocket`), so the page
 * passes `ws_url` straight to xterm.js.
 */
export const terminalApi = {
  openSession: (hostId: string) =>
    api<TerminalSessionToken>(`/api/hosts/${hostId}/terminal`, { method: "POST" }),
};

/**
 * Convenience helper for callers that want a one-shot promise-style
 * open. Same return as `terminalApi.openSession`.
 */
export function openTerminalSession(hostId: string): Promise<TerminalSessionToken> {
  return terminalApi.openSession(hostId);
}
