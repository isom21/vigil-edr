import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Building2, Check } from "lucide-react";
import { tenantsApi } from "@/api/tenants";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";

// Phase 3 #3.1: cookie name shared with the backend resolver in
// app/core/deps.py. Don't rename in one place without renaming in
// the other — the resolver only reads cookies it can find by exact
// name.
const ACTIVE_TENANT_COOKIE = "vigil_active_tenant_id";

function readCookie(name: string): string | null {
  const target = `${name}=`;
  const found = document.cookie.split("; ").find((c) => c.startsWith(target));
  return found ? decodeURIComponent(found.slice(target.length)) : null;
}

function writeCookie(name: string, value: string): void {
  // 30-day persistence is enough that a super-admin doesn't have to
  // reflip the tenant on every browser restart but short enough that
  // an abandoned laptop doesn't keep the wrong tenant active forever.
  // SameSite=Lax + Secure when the page is HTTPS — the lax mode
  // matches the rest of the SPA's same-origin posture.
  const maxAge = 60 * 60 * 24 * 30;
  const secure = window.location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; SameSite=Lax${secure}`;
}

function clearCookie(name: string): void {
  const secure = window.location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `${name}=; Max-Age=0; Path=/; SameSite=Lax${secure}`;
}

/**
 * Tenant switcher in the top bar. Visible only to super-admins.
 *
 * Persists the chosen tenant to the `vigil_active_tenant_id`
 * cookie, which the backend reads on each request to scope
 * responses. Non-super-admins never see the dropdown because the
 * backend ignores their cookie anyway — there's no point in
 * exposing the control.
 */
export function TenantSwitcher() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const isSuper = !!user?.is_super_admin;
  // Track the cookie locally so the highlight updates immediately on
  // selection. Reads on mount + on user identity change so a switch
  // between tabs picks up a cookie set elsewhere.
  const [active, setActive] = useState<string | null>(null);
  useEffect(() => {
    setActive(readCookie(ACTIVE_TENANT_COOKIE) ?? user?.tenant_id ?? null);
  }, [user?.tenant_id]);

  const tenants = useQuery({
    queryKey: ["tenants"],
    queryFn: tenantsApi.list,
    enabled: isSuper,
    staleTime: 60_000,
  });

  if (!isSuper) return null;

  const pick = (tenantId: string) => {
    if (tenantId === user?.tenant_id) {
      // Home tenant — clear the cookie so the resolver falls back to
      // user.tenant_id and a future tenant rename doesn't strand the
      // session.
      clearCookie(ACTIVE_TENANT_COOKIE);
    } else {
      writeCookie(ACTIVE_TENANT_COOKIE, tenantId);
    }
    setActive(tenantId);
    // Invalidate every fetched query — the API responses change
    // shape entirely when the active tenant flips.
    qc.invalidateQueries();
  };

  const activeRow = tenants.data?.find((t) => t.id === active);
  const label = activeRow?.slug ?? "tenant";

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="gap-2"
          aria-label="Switch tenant"
          title="Switch tenant (super-admin)"
        >
          <Building2 className="h-4 w-4" />
          <span className="max-w-[10rem] truncate">{label}</span>
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={6}
          className="z-50 min-w-[14rem] rounded-md border bg-background p-1 text-foreground shadow-md"
        >
          <div className="px-2 py-1.5 text-xs text-muted-foreground">Active tenant</div>
          <DropdownMenu.Separator className="my-1 h-px bg-border" />
          {tenants.isLoading && (
            <div className="px-2 py-1.5 text-sm text-muted-foreground">Loading…</div>
          )}
          {tenants.data?.map((t) => (
            <DropdownMenu.Item
              key={t.id}
              onSelect={() => pick(t.id)}
              className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none focus:bg-accent"
            >
              <span className="w-4">
                {t.id === active ? <Check className="h-3.5 w-3.5" /> : null}
              </span>
              <span className="flex-1 truncate">{t.slug}</span>
              {t.disabled && <span className="text-xs text-muted-foreground">(disabled)</span>}
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
