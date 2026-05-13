import { api } from "./client";
import { tokenStore } from "./tokens";
import type {
  LoginResponse,
  OidcDiscoveryResponse,
  TokenPair,
  TotpSetupResponse,
  TotpStatus,
  TotpVerifySetupResponse,
  User,
} from "@/types/api";

/**
 * Result of the password step. When `kind: "ok"`, the user is logged
 * in. When `kind: "mfa"`, the caller must collect a TOTP / recovery
 * code and POST to /api/auth/login/2fa with the included
 * `mfa_token`.
 */
export type LoginStep1Result = { kind: "ok"; user: User } | { kind: "mfa"; mfaToken: string };

export async function login(email: string, password: string): Promise<LoginStep1Result> {
  // The /login response also Set-Cookies the HttpOnly `vigil_refresh`
  // cookie (M-frontend-auth #10) when the user has no 2FA. Same-
  // origin fetch picks it up automatically; only the access token
  // needs to land in memory.
  const resp = await api<LoginResponse>("/api/auth/login", {
    method: "POST",
    body: { email, password },
  });
  if (resp.mfa_required && resp.mfa_token) {
    return { kind: "mfa", mfaToken: resp.mfa_token };
  }
  if (!resp.access_token) {
    throw new Error("login response was missing both access_token and mfa_token");
  }
  tokenStore.setTokens(resp.access_token);
  return { kind: "ok", user: await getMe() };
}

export async function login2fa(mfaToken: string, code: string): Promise<User> {
  const tokens = await api<TokenPair>("/api/auth/login/2fa", {
    method: "POST",
    body: { mfa_token: mfaToken, code },
  });
  tokenStore.setTokens(tokens.access_token);
  return getMe();
}

export async function logout(): Promise<void> {
  // Best-effort: clear the cookie server-side, then drop in-memory
  // state. We don't await ApiError handling — even if the network
  // call fails the user expects "logout" to leave them logged out.
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    });
  } catch {
    // ignore — we still clear local state below
  }
  tokenStore.clear();
}

export function getMe(): Promise<User> {
  return api<User>("/api/me");
}

/**
 * Tiny gate the Login page pings to decide whether to render the
 * "Sign in with SSO" button. Returns `{enabled: false}` when the
 * manager isn't configured for OIDC (the common dev case).
 */
export function oidcDiscovery(): Promise<OidcDiscoveryResponse> {
  return api<OidcDiscoveryResponse>("/api/auth/oidc/discovery");
}

// ---------- Self-service TOTP enrollment ----------

export const totpApi = {
  status: () => api<TotpStatus>("/api/auth/2fa/status"),
  setup: () => api<TotpSetupResponse>("/api/auth/2fa/setup", { method: "POST" }),
  verifySetup: (code: string) =>
    api<TotpVerifySetupResponse>("/api/auth/2fa/verify-setup", {
      method: "POST",
      body: { code },
    }),
  disable: (code: string) =>
    api<void>("/api/auth/2fa/disable", {
      method: "POST",
      body: { code },
    }),
};
