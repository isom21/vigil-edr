import { useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { ChevronRight, LogOut, Moon, Rows3, Rows4, Sun, User as UserIcon } from "lucide-react";
import { logout } from "@/api/auth";
import { useAuth } from "@/hooks/useAuth";
import { useUiPrefs } from "@/hooks/useUiPrefs";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const SEGMENT_LABELS: Record<string, string> = {
  dashboard: "Dashboard",
  alerts: "Alerts",
  hosts: "Hosts",
  rules: "Rules",
  commands: "Commands",
  enrollment: "Enrollment",
  users: "Users",
  new: "New",
};

function humanize(seg: string): string {
  if (SEGMENT_LABELS[seg]) return SEGMENT_LABELS[seg];
  if (/^[0-9a-f]{8}-/.test(seg)) return seg.slice(0, 8) + "…";
  return seg;
}

function Breadcrumbs() {
  const { pathname } = useLocation();
  const segs = pathname.split("/").filter(Boolean);
  if (segs.length === 0) return <div className="text-sm font-medium">Home</div>;
  return (
    <nav className="flex items-center gap-1 text-sm">
      {segs.map((seg, i) => (
        <div key={i} className="flex items-center gap-1">
          {i > 0 && <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
          <span
            className={cn(
              i === segs.length - 1 ? "font-medium text-foreground" : "text-muted-foreground",
            )}
          >
            {humanize(seg)}
          </span>
        </div>
      ))}
    </nav>
  );
}

export function TopBar() {
  const { user } = useAuth();
  const { theme, setTheme, density, setDensity } = useUiPrefs();
  const qc = useQueryClient();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    qc.clear();
    navigate("/login");
  };

  return (
    <div className="flex h-14 shrink-0 items-center justify-between border-b bg-background/60 px-6 backdrop-blur">
      <Breadcrumbs />
      <div className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="icon"
          aria-label={density === "compact" ? "Comfortable density" : "Compact density"}
          onClick={() => setDensity(density === "compact" ? "comfortable" : "compact")}
          title={density === "compact" ? "Comfortable density" : "Compact density"}
        >
          {density === "compact" ? <Rows3 className="h-4 w-4" /> : <Rows4 className="h-4 w-4" />}
        </Button>
        <Button
          variant="ghost"
          size="icon"
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <Button variant="ghost" size="sm" className="gap-2">
              <UserIcon className="h-4 w-4" />
              <span className="max-w-[12rem] truncate">{user?.email ?? "anonymous"}</span>
            </Button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content
              align="end"
              sideOffset={6}
              className="z-50 min-w-[12rem] rounded-md border bg-background p-1 text-foreground shadow-md"
            >
              <div className="px-2 py-1.5 text-xs">
                <div className="truncate font-medium">{user?.email}</div>
                <div className="text-muted-foreground">{user?.role}</div>
              </div>
              <DropdownMenu.Separator className="my-1 h-px bg-border" />
              <DropdownMenu.Item
                onSelect={handleLogout}
                className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none focus:bg-accent"
              >
                <LogOut className="h-4 w-4" />
                Sign out
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </div>
  );
}
