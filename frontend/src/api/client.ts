/**
 * Tiny fetch wrapper with auth + JSON conventions.
 *
 * - Reads access token via tokenStore (in-memory after
 *   M-frontend-auth #10).
 * - On 401, attempts a one-shot refresh via the HttpOnly cookie; on
 *   failure, clears the in-memory access token and the cookie via
 *   /api/auth/logout. The SPA's router renders the login page when
 *   the next render sees no access token.
 * - Throws ApiError({ status, detail }) on non-2xx so callers can
 *   render messages.
 */
import { tokenStore } from "./tokens";

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
    public retryAfterSeconds: number | null = null,
  ) {
    super(`${status}: ${detail}`);
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE" | "PUT";
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  signal?: AbortSignal;
}

let refreshPromise: Promise<boolean> | null = null;

async function refreshOnce(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    try {
      // Refresh rides on the HttpOnly `vigil_refresh` cookie set by
      // /login + /refresh on the server. `credentials: "include"` is
      // what makes the browser attach the cookie cross-fetch — we're
      // same-origin in dev (Vite proxy) and prod, but the explicit
      // flag is required when the call site is `fetch` rather than
      // a credentialed XHR.
      const res = await fetch("/api/auth/refresh", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      if (!res.ok) return false;
      const data = (await res.json()) as { access_token: string };
      tokenStore.setTokens(data.access_token);
      return true;
    } catch {
      return false;
    } finally {
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) params.append(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

async function doFetch(path: string, opts: RequestOptions, retried: boolean): Promise<Response> {
  const access = tokenStore.getAccessToken();
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (access) headers.Authorization = `Bearer ${access}`;

  const res = await fetch(buildUrl(path, opts.query), {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });

  if (res.status === 401 && !retried) {
    // We don't have the refresh token in JS any more (M-frontend-auth
    // #10); the cookie is the only thing that knows. Just try the
    // refresh — if the cookie is missing/expired we'll get 401 back
    // and fall through to clearing the in-memory access token.
    const ok = await refreshOnce();
    if (ok) return doFetch(path, opts, true);
    tokenStore.clear();
  }
  return res;
}

export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const res = await doFetch(path, opts, false);
  if (res.status === 204) return undefined as T;
  let body: unknown = null;
  if (res.headers.get("content-type")?.includes("application/json")) {
    body = await res.json().catch(() => null);
  }
  if (!res.ok) {
    const detail =
      (body as { detail?: string } | null)?.detail ?? res.statusText ?? "request failed";
    const retryAfterRaw = res.headers.get("Retry-After");
    const retryAfter = retryAfterRaw ? parseInt(retryAfterRaw, 10) : NaN;
    throw new ApiError(res.status, detail, Number.isFinite(retryAfter) ? retryAfter : null);
  }
  return body as T;
}
