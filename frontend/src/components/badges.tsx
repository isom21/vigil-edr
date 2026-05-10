import { SEVERITY_HSL } from "@/lib/severity";
import { cn } from "@/lib/utils";
import type { AlertState, CommandStatus, HostStatus, RuleAction, Severity } from "@/types/api";

const baseChip =
  "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap";

const severityClass: Record<Severity, string> = {
  info: "bg-sev-info/15 text-sev-info border-sev-info/30",
  low: "bg-sev-low/15 text-sev-low border-sev-low/30",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  high: "bg-sev-high/15 text-sev-high border-sev-high/30",
  critical: "bg-sev-critical/20 text-sev-critical border-sev-critical/40",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={cn(baseChip, severityClass[severity])}>
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ backgroundColor: SEVERITY_HSL[severity] }}
      />
      {severity}
    </span>
  );
}

const alertStateClass: Record<AlertState, string> = {
  new: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  investigating: "bg-sev-low/15 text-sev-low border-sev-low/30",
  false_positive: "bg-muted text-muted-foreground border-border",
  true_positive: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
};

export function AlertStateBadge({ state }: { state: AlertState }) {
  return <span className={cn(baseChip, alertStateClass[state])}>{state.replace("_", " ")}</span>;
}

const hostStatusClass: Record<HostStatus, string> = {
  pending: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  online: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  offline: "bg-muted text-muted-foreground border-border",
  isolated: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  decommissioned: "bg-muted/50 text-muted-foreground border-border",
};

export function HostStatusBadge({ status }: { status: HostStatus }) {
  return <span className={cn(baseChip, hostStatusClass[status])}>{status}</span>;
}

const cmdStatusClass: Record<CommandStatus, string> = {
  pending: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  dispatched: "bg-sev-low/15 text-sev-low border-sev-low/30",
  succeeded: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  failed: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
};

export function CommandStatusBadge({ status }: { status: CommandStatus }) {
  return <span className={cn(baseChip, cmdStatusClass[status])}>{status}</span>;
}

const actionClass: Record<RuleAction, string> = {
  detect: "bg-sev-low/15 text-sev-low border-sev-low/30",
  kill: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  block: "bg-sev-high/15 text-sev-high border-sev-high/30",
};

export function RuleActionBadge({ action }: { action: RuleAction }) {
  return <span className={cn(baseChip, actionClass[action])}>{action}</span>;
}
