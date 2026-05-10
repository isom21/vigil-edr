// Types mirror app/schemas/*.py on the backend. Keep in sync manually for now;
// codegen is a future improvement (openapi-typescript would generate these from /api/openapi.json).

export type UserRole = "admin" | "analyst" | "viewer";
export type OsFamily = "windows" | "linux" | "macos";
export type HostStatus = "pending" | "online" | "offline" | "isolated" | "decommissioned";
export type RuleKind = "yara" | "sigma" | "ioc";
export type RuleAction = "detect" | "kill" | "block";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type IocKind = "hash_sha256" | "hash_md5" | "hash_sha1" | "filename" | "filepath";
export type AlertState = "new" | "investigating" | "false_positive" | "true_positive";

export interface User {
  id: string;
  email: string;
  role: UserRole;
  disabled: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface Host {
  id: string;
  hostname: string;
  os_family: OsFamily;
  os_version: string | null;
  os_platform: string | null;
  os_arch: string | null;
  agent_version: string | null;
  status: HostStatus;
  enrolled_at: string | null;
  last_seen_at: string | null;
  policy_id: string | null;
}

export interface IocEntry {
  id: string;
  kind: IocKind;
  value: string;
}

export interface Rule {
  id: string;
  kind: RuleKind;
  name: string;
  description: string | null;
  severity: Severity;
  action: RuleAction;
  enabled: boolean;
  body: string | null;
  revision: number;
  created_at: string;
  updated_at: string;
  iocs: IocEntry[];
}

export interface RuleCreate {
  kind: RuleKind;
  name: string;
  description?: string | null;
  severity?: Severity;
  action?: RuleAction;
  enabled?: boolean;
  body?: string | null;
  iocs?: { kind: IocKind; value: string }[];
}

export interface AlertHistory {
  id: string;
  from_state: AlertState | null;
  to_state: AlertState;
  by_user_id: string | null;
  comment: string | null;
  ts: string;
}

export interface Alert {
  id: string;
  host_id: string;
  rule_id: string;
  severity: Severity;
  action_taken: RuleAction;
  state: AlertState;
  summary: string;
  details: Record<string, unknown> | null;
  telemetry_index: string | null;
  telemetry_doc_ids: string[] | null;
  opened_at: string;
  closed_at: string | null;
  assignee_id: string | null;
  created_at: string;
  updated_at: string;
  // M7.7 list/detail enrichment.
  host_hostname?: string | null;
  rule_name?: string | null;
}

export interface AlertDetail extends Alert {
  history: AlertHistory[];
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface EnrollmentToken {
  id: string;
  label: string | null;
  expires_at: string;
  used_at: string | null;
  created_at: string;
}

export interface EnrollmentTokenCreated extends EnrollmentToken {
  token: string; // plaintext shown once
}

export interface ApiToken {
  id: string;
  name: string;
  scopes: string[];
  last_used_at: string | null;
  revoked_at: string | null;
  expires_at: string | null;
  created_at: string;
}

export interface ApiTokenCreated extends ApiToken {
  token: string;
}

// M7.5 host groups
export interface HostGroup {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
  host_count: number;
  user_count: number;
}

// M7.7 chart strip aggregations.
export interface StatBucket {
  key: string;
  count: number;
}

// M5/M7.6 response-action commands.
export type CommandKind =
  | "kill_process"
  | "block_process"
  | "block_file"
  | "unblock_process"
  | "unblock_file"
  | "scan_file"
  | "scan_memory"
  | "isolate"
  | "update";

export type CommandStatus = "pending" | "dispatched" | "succeeded" | "failed";

export interface Command {
  id: string;
  host_id: string;
  kind: CommandKind;
  status: CommandStatus;
  payload: Record<string, unknown>;
  triggered_by_alert_id: string | null;
  triggered_by_rule_id: string | null;
  issued_by_user_id: string | null;
  dispatched_at: string | null;
  completed_at: string | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}
