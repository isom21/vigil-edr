import { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import {
  AlertTriangle,
  KeyRound,
  LayoutDashboard,
  Server,
  Shield,
  Terminal,
  Users,
} from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { TopBar } from "@/components/TopBar";
import { cn } from "@/lib/utils";
import { APP_VERSION } from "@/lib/version";

interface NavItem {
  to: string;
  label: string;
  icon: typeof Server;
  adminOnly?: boolean;
}

interface NavSection {
  heading: string;
  items: NavItem[];
}

const SECTIONS: NavSection[] = [
  {
    heading: "Triage",
    items: [
      { to: "/alerts", label: "Alerts", icon: AlertTriangle },
      { to: "/commands", label: "Commands", icon: Terminal },
    ],
  },
  {
    heading: "Fleet",
    items: [
      { to: "/hosts", label: "Hosts", icon: Server },
      { to: "/enrollment", label: "Enrollment", icon: KeyRound },
    ],
  },
  {
    heading: "Detection",
    items: [{ to: "/rules", label: "Rules", icon: Shield }],
  },
  {
    heading: "Overview",
    items: [{ to: "/dashboard", label: "Dashboard", icon: LayoutDashboard }],
  },
  {
    heading: "Admin",
    items: [{ to: "/users", label: "Users", icon: Users, adminOnly: true }],
  },
];

export function Layout({ children }: { children: ReactNode }) {
  const { user } = useAuth();

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 shrink-0 flex-col border-r">
        <div className="flex h-14 items-center gap-2 border-b px-5">
          <Shield className="h-5 w-5" />
          <span className="text-base font-semibold">Vigil</span>
          <span className="ml-auto text-[10px] uppercase tracking-wider text-muted-foreground">
            v{APP_VERSION}
          </span>
        </div>
        <nav className="flex-1 space-y-4 overflow-y-auto p-3">
          {SECTIONS.map((section) => {
            const items = section.items.filter((i) => !i.adminOnly || user?.role === "admin");
            if (items.length === 0) return null;
            return (
              <div key={section.heading}>
                <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {section.heading}
                </div>
                <div className="space-y-0.5">
                  {items.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      className={({ isActive }) =>
                        cn(
                          "flex items-center gap-3 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
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
                </div>
              </div>
            );
          })}
        </nav>
      </aside>
      <main className="flex flex-1 flex-col overflow-hidden">
        <TopBar />
        <div className="flex-1 overflow-auto">{children}</div>
      </main>
    </div>
  );
}
