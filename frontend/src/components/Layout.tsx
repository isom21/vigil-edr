import { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import {
  AlertTriangle,
  Archive,
  Briefcase,
  FileLock,
  Flame,
  KeyRound,
  LayoutDashboard,
  Rss,
  Server,
  Shield,
  Terminal,
  Users,
} from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { AlertStreamToasts } from "@/components/AlertStreamToasts";
import { HotkeysProvider } from "@/components/HotkeysProvider";
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
      { to: "/incidents", label: "Incidents", icon: Flame },
      { to: "/jobs", label: "Jobs", icon: Briefcase },
      { to: "/commands", label: "Commands", icon: Terminal },
      { to: "/quarantine", label: "Quarantine", icon: Archive },
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
    heading: "Operations",
    items: [{ to: "/intel", label: "Threat intel", icon: Rss }],
  },
  {
    heading: "Overview",
    items: [{ to: "/dashboard", label: "Dashboard", icon: LayoutDashboard }],
  },
  {
    heading: "Admin",
    items: [
      { to: "/users", label: "Users", icon: Users, adminOnly: true },
      { to: "/audit", label: "Audit log", icon: FileLock, adminOnly: true },
    ],
  },
];

export function Layout({ children }: { children: ReactNode }) {
  const { user } = useAuth();

  return (
    <div className="flex min-h-screen">
      {/* Skip-link for keyboard / screen-reader users. Hidden visually
          until focused, then jumps focus past the sidebar. */}
      <a
        href="#main"
        className="absolute left-2 top-2 z-50 -translate-y-full rounded-md bg-card px-3 py-2 text-sm font-medium shadow-lg ring-2 ring-ring focus-visible:translate-y-0"
      >
        Skip to main content
      </a>
      <aside className="flex w-56 shrink-0 flex-col border-r">
        <div className="flex h-14 items-center gap-2 border-b px-5">
          <Shield className="h-5 w-5" aria-hidden="true" />
          <span className="text-base font-semibold">Vigil</span>
          <span
            className="ml-auto text-[10px] uppercase tracking-wider text-muted-foreground tabular-nums"
            translate="no"
          >
            v&nbsp;{APP_VERSION}
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
                          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                          isActive
                            ? "bg-secondary text-secondary-foreground"
                            : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground",
                        )
                      }
                    >
                      <item.icon className="h-4 w-4" aria-hidden="true" />
                      {item.label}
                    </NavLink>
                  ))}
                </div>
              </div>
            );
          })}
        </nav>
      </aside>
      <main id="main" className="flex flex-1 flex-col overflow-hidden">
        <TopBar />
        <div className="flex-1 overflow-auto">{children}</div>
      </main>
      {/* M22.b: SSE alert stream + toast notifier. Mounted at layout
          level so it survives route changes. */}
      <AlertStreamToasts />
      {/* M22.e: global keyboard shortcuts + cheat-sheet modal. */}
      <HotkeysProvider />
    </div>
  );
}
