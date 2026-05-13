import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getMe } from "@/api/auth";
import { tokenStore } from "@/api/tokens";
import type { User } from "@/types/api";

export function useAuth() {
  const qc = useQueryClient();
  const [hasToken, setHasToken] = useState(!!tokenStore.getAccessToken());

  useEffect(() => tokenStore.subscribe(() => setHasToken(!!tokenStore.getAccessToken())), []);

  const me = useQuery<User>({
    queryKey: ["me"],
    queryFn: getMe,
    enabled: hasToken,
    retry: false,
    staleTime: 5 * 60_000,
  });

  return {
    user: me.data ?? null,
    isLoading: hasToken && me.isLoading,
    isAuthenticated: hasToken && !!me.data,
    // Phase 3 #3.1: surface multi-tenancy bits so callers don't have
    // to peek at me.data?.is_super_admin themselves.
    isSuperAdmin: !!me.data?.is_super_admin,
    tenantId: me.data?.tenant_id ?? null,
    refresh: () => qc.invalidateQueries({ queryKey: ["me"] }),
  };
}
