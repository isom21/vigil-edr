import type { AlertState, Severity } from "@/types/api";

export const severityColor = (s: Severity): string => `hsl(var(--sev-${s}))`;

export const SEVERITY_HSL: Record<Severity, string> = {
  info: "hsl(var(--sev-info))",
  low: "hsl(var(--sev-low))",
  medium: "hsl(var(--sev-medium))",
  high: "hsl(var(--sev-high))",
  critical: "hsl(var(--sev-critical))",
};

const LABEL: Record<Severity, string> = {
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

export const severityLabel = (s: Severity): string => LABEL[s];

/** Bulk triage actions surfaced on the alerts table. */
export const ALERT_TRANSITIONS: {
  to: AlertState;
  label: string;
  variant: "default" | "outline" | "destructive" | "secondary";
}[] = [
  { to: "investigating", label: "Move to investigating", variant: "outline" },
  { to: "false_positive", label: "Mark false positive", variant: "secondary" },
  { to: "true_positive", label: "Mark true positive", variant: "destructive" },
];
