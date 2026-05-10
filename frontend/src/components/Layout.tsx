import { ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Server,
  Shield,
  Terminal,
  Users,
} from "lucide-react";
import { logout } from "@/api/auth";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/hosts", label: "Hosts", icon: Server },
  { to: "/rules", label: "Rules", icon: Shield },
  { to: "/alerts", label: "Alerts", icon: AlertTriangle },
  { to: "/commands", label: "Commands", icon: Terminal },
  { to: "/enrollment", label: "Enrollment", icon: KeyRound },
  { to: "/users", label: "Users", icon: Users, adminOnly: true },
];

export function Layout({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const qc = useQueryClient();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    qc.clear();
    navigate("/login");
  };

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-60 shrink-0 flex-col border-r bg-card">
        <div className="border-b px-6 py-4">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            <span className="text-lg font-semibold">EDR Manager</span>
          </div>
          <div className="mt-1 text-xs text-muted-foreground">v0.1.0 • PoC</div>
        </div>
        <nav className="flex-1 space-y-1 p-3">
          {NAV.filter((n) => !n.adminOnly || user?.role === "admin").map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-secondary text-secondary-foreground"
                    : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground",
                )
              }
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t p-3">
          <div className="px-3 py-2 text-xs text-muted-foreground">
            <div className="truncate font-medium text-foreground">{user?.email}</div>
            <div>{user?.role}</div>
          </div>
          <Button variant="ghost" className="mt-1 w-full justify-start" onClick={handleLogout}>
            <LogOut className="h-4 w-4" />
            Sign out
          </Button>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  );
}
