// Types mirror app/schemas/*.py on the backend. Keep in sync manually for now;
// codegen is a future improvement (openapi-typescript would generate these from /api/openapi.json).

export type UserRole = "admin" | "analyst" | "viewer";
export type OsFamily = "windows" | "linux" | "macos";
export type HostStatus = "pending" | "online" | "offline" | "isolated" | "decommissioned";
export type RuleKind = "yara" | "sigma" | "ioc";
export type RuleAction = "alert" | "block" | "quarantine";
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
  totp_enabled: boolean;
  // Phase 3 #3.1: tenant + super-admin bit. Non-super-admins are
  // pinned to their home tenant; super-admins can flip the active
  // tenant via the `vigil_active_tenant_id` cookie the switcher sets.
  tenant_id: string;
  is_super_admin: boolean;
}

// Phase 3 #3.1: tenant payload mirrors app/schemas/tenant.py.
export interface Tenant {
  id: string;
  slug: string;
  name: string;
  disabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface TenantCreate {
  slug: string;
  name: string;
}

export interface TenantUpdate {
  name?: string;
  disabled?: boolean;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

// /api/auth/login can return either a TokenPair (no 2FA) or an
// MFA-pending challenge. The fields overlap so we model them as one
// shape with optional values, matching the backend's LoginResponse.
export interface LoginResponse {
  access_token: string | null;
  refresh_token: string | null;
  token_type: string;
  mfa_required: boolean;
  mfa_token: string | null;
}

export interface TotpStatus {
  enabled: boolean;
  pending: boolean;
}

export interface TotpSetupResponse {
  secret_base32: string;
  provisioning_uri: string;
}

export interface TotpVerifySetupResponse {
  enabled: boolean;
  recovery_codes: string[];
}

export interface OidcDiscoveryResponse {
  enabled: boolean;
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

// Phase 2 #2.9 — container telemetry surfaces on host detail + alert detail.
export interface ContainerInfo {
  id: string;
  image: string | null;
  runtime: string | null;
}

export interface HostDetail extends Host {
  /** 24h-rolling list of container runtimes that emitted process
   * events on this host, sorted by count desc, capped at 5. Empty
   * when no container telemetry was recorded. */
  container_runtimes_seen: string[];
  /** Phase 4 #4.10: TPM attestation status block. Null when the
   * manager couldn't compute one (extremely rare — should always be
   * populated for non-decommissioned hosts). */
  attestation: AttestationBlock | null;
}

// ---- Phase 4 #4.10 — TPM-backed boot-state attestation ----

export type AttestationStatus = "ok" | "diverged" | "unverified" | "unknown";

export interface PcrValue {
  index: number;
  bank: string;
  digest_hex: string;
}

export interface AttestationGolden {
  host_id: string;
  pcr_values_json: PcrValue[];
  ak_cert_fingerprint: string | null;
  recorded_at: string;
  recorded_by_user_id: string | null;
}

export interface AttestationEvent {
  id: string;
  host_id: string;
  pcr_values_json: PcrValue[];
  matches_golden: boolean;
  diverged_pcrs: number[];
  recorded_at: string;
}

export interface AttestationBlock {
  status: AttestationStatus;
  latest: AttestationEvent | null;
  golden: AttestationGolden | null;
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
  group_id: string | null;
  created_at: string;
  updated_at: string;
  iocs: IocEntry[];
  // Phase 1 #1.8: MITRE ATT&CK technique IDs (e.g. ["T1059.001"]).
  mitre_techniques: string[] | null;
  // Phase 2 #2.1: auto-queue a memory YARA job when an alert from this
  // rule carries a process.pid.
  auto_memory_scan: boolean;
}

export interface RuleCreate {
  kind: RuleKind;
  name: string;
  description?: string | null;
  severity?: Severity;
  action?: RuleAction;
  enabled?: boolean;
  body?: string | null;
  group_id?: string | null;
  iocs?: { kind: IocKind; value: string }[];
  mitre_techniques?: string[] | null;
  auto_memory_scan?: boolean;
}

// M20.b rule groups
export interface RuleGroup {
  id: string;
  kind: RuleKind;
  name: string;
  description: string | null;
  max_action: RuleAction;
  rule_count: number;
  created_at: string;
  updated_at: string;
}

export interface RuleGroupCreate {
  kind: RuleKind;
  name: string;
  description?: string | null;
  max_action?: RuleAction;
}

export interface RuleGroupUpdate {
  name?: string;
  description?: string | null;
  max_action?: RuleAction;
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
  // Null for synthetic / manager-internal alerts (e.g. audit chain
  // break). UI renders these as host="System".
  host_id: string | null;
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
  // Phase 1 #1.10 alert deduplication. `occurrence_count` is the
  // number of detections folded onto this row (1 for a never-deduped
  // alert); `last_occurred_at` is the timestamp of the most recent
  // detection.
  occurrence_count: number;
  last_occurred_at: string;
  // Phase 1 #1.8: MITRE ATT&CK technique IDs frozen from the rule at
  // fire time.
  mitre_techniques?: string[] | null;
  // M7.7 list/detail enrichment.
  host_hostname?: string | null;
  rule_name?: string | null;
}

export interface AlertDetail extends Alert {
  history: AlertHistory[];
  /** Phase 2 #2.9: container attribution lifted from the alert's
   * triggering process_started doc. Null on hosts without the
   * container_v1-capable agent, or bare-metal processes. */
  container?: ContainerInfo | null;
  /** Phase 3 #3.6: per-destination external case mirrors. Populated
   * when the alert lifecycle hook pushed this alert into one or more
   * Jira / ServiceNow destinations. Empty when no case destinations
   * are registered or none have accepted the alert. */
  case_links?: CaseLink[];
}

// Phase 1 #1.11 — incidents (alert grouping).
export type IncidentStatus = "open" | "investigating" | "resolved" | "closed";

// Phase 2 #2.13 — why the alerts ended up in this incident.
export type IncidentGroupingReason = "window" | "process_tree" | "rule_cluster";

export interface Incident {
  id: string;
  host_id: string | null;
  title: string;
  summary: string | null;
  severity: Severity;
  status: IncidentStatus;
  opened_at: string;
  closed_at: string | null;
  assignee_id: string | null;
  created_at: string;
  updated_at: string;
  grouping_reason: IncidentGroupingReason;
  host_hostname?: string | null;
  alert_count: number;
}

export interface IncidentDetail extends Incident {
  alerts: Alert[];
}

// M20.d alert investigation page payload.
export interface ProcessChainNode {
  pid: number;
  parent_pid: number | null;
  name: string | null;
  executable: string | null;
  command_line: string | null;
  sha256: string | null;
  user_name: string | null;
  integrity_level: string | null;
  working_directory: string | null;
  started_at: string | null;
  event_id: string | null;
  inferred: boolean;
  /** Other processes spawned by this node's parent that aren't on the
   * alert path. Populated only one level deep — siblings have empty
   * siblings arrays themselves. */
  siblings: ProcessChainNode[];
  /** Direct children spawned by THIS process. Populated only for the
   * leaf node (the alert-triggering process). */
  children: ProcessChainNode[];
}

export interface TimelineEvent {
  event_id: string;
  timestamp: string;
  category: string[];
  action: string | null;
  outcome: string | null;
  pid: number | null;
  executable: string | null;
  command_line: string | null;
  file_path: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  is_trigger: boolean;
}

export interface AlertContext {
  alert_id: string;
  host_id: string;
  host_hostname: string | null;
  rule_id: string;
  rule_name: string | null;
  opened_at: string;
  window_start: string;
  window_end: string;
  trigger_event_ids: string[];
  chain: ProcessChainNode[];
  events: TimelineEvent[];
  events_truncated: boolean;
}

// M20.i: selected-process detail panel.
export interface ProcessFileEvent {
  timestamp: string;
  action: string | null;
  path: string | null;
  target_path: string | null;
  sha256: string | null;
  size: number | null;
}

export interface ProcessImageLoad {
  timestamp: string;
  path: string | null;
  sha256: string | null;
  signed: boolean | null;
  signer: string | null;
}

export interface ProcessNetworkEvent {
  timestamp: string;
  action: string | null;
  transport: string | null;
  direction: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  source_ip: string | null;
  source_port: number | null;
}

export interface ProcessOtherEvent {
  timestamp: string;
  category: string[];
  action: string | null;
  outcome: string | null;
}

export interface ProcessDetail {
  alert_id: string;
  host_id: string;
  pid: number;
  window_start: string;
  window_end: string;
  process: ProcessChainNode | null;
  image_loads: ProcessImageLoad[];
  files: ProcessFileEvent[];
  network: ProcessNetworkEvent[];
  other: ProcessOtherEvent[];
  truncated: boolean;
}

// Phase 2 #2.6: cross-process correlation graph store. Distinct from
// the OpenSearch-shaped `ProcessChainNode` above — these come from the
// Postgres `process_chain` table and only carry the durable fields the
// graph store persists (no user_name/integrity/working_directory/
// siblings/children).
export interface ProcessChainNodePG {
  id: string;
  host_id: string;
  pid: number;
  parent_pid: number | null;
  exec_path: string | null;
  image_sha256: string | null;
  command_line: string | null;
  started_at: string;
  ended_at: string | null;
}

export interface ProcessChainResponse {
  host_id: string;
  pid: number;
  ancestors: ProcessChainNodePG[];
  descendants: ProcessChainNodePG[];
}

// M20.j live host telemetry feed.
export interface LiveTelemetryEvent {
  event_id: string;
  timestamp: string;
  category: string[];
  action: string | null;
  outcome: string | null;

  // process.*
  pid: number | null;
  parent_pid: number | null;
  executable: string | null;
  command_line: string | null;
  working_directory: string | null;
  user_name: string | null;

  // file.*
  file_path: string | null;
  file_action: string | null;
  file_size: number | null;

  // network.* / source / destination
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  destination_domain: string | null;
  transport: string | null;
  direction: string | null;

  // dns.*
  dns_question_name: string | null;

  // library / module load
  module_path: string | null;
  module_signed: boolean | null;
  module_signer: string | null;

  // event provider / code / rule attribution
  event_provider: string | null;
  event_code: string | null;
  rule_name: string | null;
  sha256: string | null;
}

export interface LiveTelemetryPage {
  host_id: string;
  events: LiveTelemetryEvent[];
  latest_timestamp: string | null;
  truncated: boolean;
}

// M22.d audit log viewer.
export interface AuditEntry {
  id: string;
  seq: number;
  ts: string;
  actor_kind: string;
  user_id: string | null;
  api_token_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  payload: Record<string, unknown> | null;
  ip: string | null;
}

// Phase 2 #2.11 threat-hunting workbench.
export type HuntQueryLanguage = "lucene" | "kql" | "sigma";
export type HuntSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface SavedHunt {
  id: string;
  owner_user_id: string;
  name: string;
  description: string | null;
  query_dsl: string;
  query_language: HuntQueryLanguage;
  schedule_cron: string | null;
  last_run_at: string | null;
  last_run_hit_count: number | null;
  alert_on_hit: boolean;
  severity: HuntSeverity | null;
  mitre_techniques: string[] | null;
  host_scope_json: Record<string, unknown> | null;
  managed_rule_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface SavedHuntCreate {
  name: string;
  description?: string | null;
  query_dsl: string;
  query_language: HuntQueryLanguage;
  schedule_cron?: string | null;
  alert_on_hit?: boolean;
  severity?: HuntSeverity | null;
  mitre_techniques?: string[] | null;
  host_scope_json?: Record<string, unknown> | null;
}

export type SavedHuntUpdate = Partial<SavedHuntCreate>;

export interface HuntRun {
  id: string;
  hunt_id: string;
  started_at: string;
  finished_at: string | null;
  hit_count: number | null;
  error: string | null;
  alert_count: number | null;
}

export interface HuntResultHit {
  timestamp: string | null;
  host_id: string | null;
  event_id: string | null;
  source: Record<string, unknown>;
}

export interface HuntRunResult {
  query_dsl: string;
  total: number;
  hits: HuntResultHit[];
  truncated: boolean;
  run: HuntRun | null;
}

export interface HuntAdhocRequest {
  query: string;
  language: HuntQueryLanguage;
  lookback_hours?: number;
  size?: number;
}

// Phase 1 #1.9 threat-intel feeds.
export type IntelFeedKind = "taxii" | "abusech_csv" | "custom_json";

export interface IntelFeed {
  id: string;
  name: string;
  kind: IntelFeedKind;
  url: string;
  has_auth: boolean;
  interval_s: number;
  last_pulled_at: string | null;
  entry_count: number;
  last_error: string | null;
  enabled: boolean;
  managed_rule_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface IntelFeedCreate {
  name: string;
  kind: IntelFeedKind;
  url: string;
  auth?: string | null;
  interval_s?: number;
  enabled?: boolean;
}

export interface IntelFeedUpdate {
  name?: string;
  url?: string;
  auth?: string | null;
  interval_s?: number;
  enabled?: boolean;
}

// Phase 4 #4.2 — operator-registered AWS CloudTrail S3 buckets. The
// IAM-anomaly monitor walks each enabled source on its cadence and
// fires synthetic alerts when fresh events escape the per-(source,
// principal) baseline.
export type CloudSourceKind = "aws_cloudtrail";

export interface CloudSource {
  id: string;
  name: string;
  kind: CloudSourceKind;
  enabled: boolean;
  bucket: string;
  prefix: string;
  region: string;
  aws_access_key_id: string;
  has_credentials: boolean;
  last_polled_at: string | null;
  last_event_ts: string | null;
  created_at: string;
  updated_at: string;
}

// Phase 4 #4.3 identity threat detection sources.
export type IdentitySourceKind = "okta" | "azure_ad";

export interface IdentitySource {
  id: string;
  kind: IdentitySourceKind;
  name: string;
  enabled: boolean;
  last_polled_at: string | null;
  last_event_ts: string | null;
  created_at: string;
  updated_at: string;
}

export interface CloudSourceCreate {
  name: string;
  kind: CloudSourceKind;
  bucket: string;
  prefix?: string;
  region?: string;
  aws_access_key_id: string;
  aws_secret_access_key: string;
  enabled?: boolean;
}

export interface CloudSourceUpdate {
  name?: string;
  bucket?: string;
  prefix?: string;
  region?: string;
  aws_access_key_id?: string;
  aws_secret_access_key?: string;
  enabled?: boolean;
}

export interface IdentitySourceCreate {
  kind: IdentitySourceKind;
  name: string;
  config: Record<string, string>;
  enabled?: boolean;
}

export interface IdentitySourceUpdate {
  name?: string;
  config?: Record<string, string>;
  enabled?: boolean;
}

// Phase 2 #2.7 vulnerability assessment.
export interface Vulnerability {
  cve_id: string;
  severity: string | null;
  cvss_v3_score: string | null;
  summary: string | null;
  references_json: string[];
  affected_cpe_json: string[];
  published_at: string | null;
  modified_at: string | null;
  created_at: string;
}

export interface HostVulnerability {
  id: string;
  host_id: string;
  cve_id: string;
  cpe: string | null;
  first_seen: string;
  last_seen: string;
  suppressed: boolean;
  suppressed_at: string | null;
  suppressed_by_user_id: string | null;
  // Joined-in CVE fields the list view needs.
  severity: string | null;
  cvss_v3_score: string | null;
  summary: string | null;
}

// Phase 2 #2.3 — sequence / behavioral rules.
export interface SequenceRule {
  id: string;
  name: string;
  description: string | null;
  yaml_body: string;
  window_s: number;
  enabled: boolean;
  severity: Severity;
  mitre_techniques: string[] | null;
  hit_count: number;
  last_hit_at: string | null;
  managed_rule_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface SequenceRuleCreate {
  name: string;
  description?: string | null;
  yaml_body: string;
  window_s?: number;
  enabled?: boolean;
  severity?: Severity;
  mitre_techniques?: string[] | null;
}

export interface SequenceRuleUpdate {
  name?: string;
  description?: string | null;
  yaml_body?: string;
  window_s?: number;
  enabled?: boolean;
  severity?: Severity;
  mitre_techniques?: string[] | null;
}

// Phase 3 #3.5 — playbook / runbook automation.
export type PlaybookRunStatus = "pending" | "running" | "succeeded" | "failed" | "partial";

// One step's recorded outcome on a PlaybookRun. The engine writes a
// fresh object per step with at least `kind`, `outcome`, `started_at`,
// `finished_at`. Additional keys depend on the kind (e.g. `command_id`
// on isolate, `truthy` on branch_if).
export interface PlaybookStep {
  kind: string;
  params?: Record<string, unknown>;
  outcome: "ok" | "skipped" | "failed";
  started_at?: string;
  finished_at?: string;
  reason?: string;
  error?: string;
  command_id?: string;
  channel_id?: string;
  truthy?: boolean;
  skipped_next?: boolean;
  [key: string]: unknown;
}

export interface Playbook {
  id: string;
  name: string;
  description: string | null;
  yaml_body: string;
  enabled: boolean;
  trigger_rule_id: string | null;
  trigger_severity: "low" | "medium" | "high" | "critical" | null;
  trigger_mitre_techniques: string[] | null;
  created_at: string;
  updated_at: string;
}

export interface PlaybookCreate {
  name: string;
  description?: string | null;
  yaml_body: string;
  enabled?: boolean;
  trigger_rule_id?: string | null;
  trigger_severity?: "low" | "medium" | "high" | "critical" | null;
  trigger_mitre_techniques?: string[] | null;
}

export interface PlaybookUpdate {
  name?: string;
  description?: string | null;
  yaml_body?: string;
  enabled?: boolean;
  trigger_rule_id?: string | null;
  trigger_severity?: "low" | "medium" | "high" | "critical" | null;
  trigger_mitre_techniques?: string[] | null;
}

export interface PlaybookRun {
  id: string;
  playbook_id: string;
  alert_id: string | null;
  started_at: string;
  finished_at: string | null;
  status: PlaybookRunStatus;
  steps_executed_json: PlaybookStep[];
  error: string | null;
}

// M20.c quarantine inventory + release.
export type QuarantineStatus = "active" | "released" | "deleted";

export interface QuarantinedFile {
  id: string;
  host_id: string;
  host_hostname?: string | null;
  alert_id: string | null;
  command_id: string | null;
  original_path: string;
  sha256: string;
  size_bytes: number;
  deleted_original: boolean;
  quarantined_at: string;
  released_at: string | null;
  status: QuarantineStatus;
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

// Phase 3 #3.8 — SCIM bearer tokens for IdP-side provisioning.
// `token` is only present on the create response and never returned in
// the list view (the backend stores only a sha256 hash).
export interface ScimToken {
  id: string;
  label: string;
  last_used_at: string | null;
  created_at: string;
  disabled: boolean;
}

export interface ScimTokenCreated extends ScimToken {
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

// Phase 1 #1.7 — alert routing channels + rules.
export type NotificationChannelKind = "slack" | "pagerduty" | "email";

export interface NotificationChannel {
  id: string;
  name: string;
  kind: NotificationChannelKind;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  // sha256(first-8 hex) over the per-kind secret fields. Lets the
  // operator confirm a rotation took effect without ever surfacing
  // the secret itself.
  secret_fingerprint: string | null;
}

export interface RoutingRule {
  id: string;
  name: string;
  min_severity: Severity;
  rule_kind: RuleKind | null;
  host_group_id: string | null;
  channel_ids: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
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
  | "update"
  | "quarantine_file"
  | "release_quarantine";

export type CommandStatus = "pending" | "dispatched" | "succeeded" | "failed";

export interface Command {
  id: string;
  host_id: string;
  host_hostname?: string | null;
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

// M23.b Jobs engine ------------------------------------------------

export type JobKind =
  | "kill_process"
  | "delete_file"
  | "isolate"
  | "unisolate"
  | "block_process"
  | "unblock_process"
  | "block_file"
  | "unblock_file"
  | "quarantine_file"
  | "release_quarantine"
  | "file_acquire"
  | "process_memory_dump"
  | "event_log_acquire"
  | "crash_dump_collect"
  | "triage_collect"
  | "process_snapshot"
  | "network_snapshot"
  | "installed_software"
  | "persistence_audit"
  | "service_audit"
  | "account_audit"
  | "dns_history"
  | "usb_history"
  | "registry_query"
  | "browser_history"
  | "host_sweep"
  | "yara_fs_scan"
  | "ioc_sweep"
  | "hash_files"
  | "agent_diagnostic"
  | "shell_command"
  | "scan_file"
  | "scan_memory"
  | "update";

export type JobScopeKind = "host_ids" | "host_group" | "all_online";
export type JobStatus = "queued" | "running" | "completed" | "failed" | "canceled";
export type JobRunStatus =
  | "queued"
  | "dispatched"
  | "running"
  | "completed"
  | "failed"
  | "canceled"
  | "timeout";
export type JobArtifactKind =
  | "json"
  | "file"
  | "yara_matches"
  | "ioc_matches"
  | "hash_list"
  | "shell_output"
  | "diagnostic_bundle";

export interface JobArtifact {
  id: string;
  job_run_id: string;
  kind: JobArtifactKind;
  bucket: string;
  object_key: string;
  size_bytes: number;
  sha256: string | null;
  artifact_metadata: Record<string, unknown>;
  expires_at: string | null;
  downloaded_by_user_id: string | null;
  downloaded_at: string | null;
  created_at: string;
}

export interface JobRun {
  id: string;
  job_id: string;
  host_id: string;
  host_hostname?: string | null;
  command_id: string | null;
  status: JobRunStatus;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  progress_pct: number;
  progress_message: string | null;
  last_progress_at: string | null;
  artifact_count: number;
  created_at: string;
  updated_at: string;
}

export interface Job {
  id: string;
  kind: JobKind;
  parameters: Record<string, unknown>;
  scope_kind: JobScopeKind;
  scope_host_ids: string[] | null;
  scope_group_id: string | null;
  status: JobStatus;
  summary: string;
  created_by_user_id: string | null;
  triggered_by_alert_id: string | null;
  triggered_by: string;
  canceled_at: string | null;
  created_at: string;
  updated_at: string;
  run_count: number;
  run_completed: number;
  run_failed: number;
}

export interface JobDetail extends Job {
  runs: JobRun[];
}

export interface JobScope {
  kind: JobScopeKind;
  host_ids?: string[];
  group_id?: string;
}

export interface JobCreateBody {
  kind: JobKind;
  parameters: Record<string, unknown>;
  scope: JobScope;
  summary?: string;
}

export interface ArtifactDownload {
  url: string;
  expires_at: string;
}

// Phase 1 #1.4 — live-response remote shell.
export interface TerminalSessionToken {
  session_id: string;
  token: string;
  expires_at: string;
  /** Relative URL the frontend opens as a WebSocket. */
  ws_url: string;
}

// Phase 1 #1.5 — SIEM forwarders ----------------------------------

export type SiemKind = "syslog_cef" | "splunk_hec" | "sentinel_hub";

export interface SiemDestination {
  id: string;
  name: string;
  kind: SiemKind;
  enabled: boolean;
  last_send_at: string | null;
  lag_seconds: number;
  error_count: number;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface SiemDestinationCreate {
  name: string;
  kind: SiemKind;
  enabled?: boolean;
  config: Record<string, unknown>;
}

export interface SiemDestinationUpdate {
  name?: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
}

// Phase 2 #2.8 — application allowlist (learn → enforce).
export type AllowlistMode = "off" | "learn" | "enforce";

export interface AllowlistModeOut {
  host_group_id: string;
  mode: AllowlistMode;
  enabled_at: string | null;
  learn_started_at: string | null;
  learn_completed_at: string | null;
  updated_at: string;
  entry_count: number;
}

export interface AllowlistEntry {
  id: string;
  host_group_id: string;
  sha256: string;
  exec_path: string | null;
  publisher: string | null;
  first_seen: string | null;
  last_seen: string | null;
  learned: boolean;
  manual: boolean;
  created_at: string;
  updated_at: string;
}

export interface AllowlistEntryCreate {
  sha256: string;
  exec_path?: string | null;
  publisher?: string | null;
}

// Phase 3 #3.2 — OpenSearch ILM + S3 cold archive.
export type ArchiveJobStatus =
  | "pending"
  | "freezing"
  | "frozen"
  | "rehydrating"
  | "rehydrated"
  | "failed";

export interface ArchiveJob {
  id: string;
  index_name: string;
  status: ArchiveJobStatus;
  started_at: string | null;
  finished_at: string | null;
  doc_count: number | null;
  s3_key: string | null;
  error: string | null;
  created_at: string;
}

// Phase 2 #2.12 — DNS sinkhole / domain block list -------------------

export type DnsBlockAction = "block" | "sinkhole";

export interface DnsBlockEntry {
  id: string;
  host_group_id: string | null;
  domain: string;
  action: DnsBlockAction;
  created_by_user_id: string | null;
  created_at: string;
  expires_at: string | null;
  hits: number;
  last_hit_at: string | null;
}

export interface DnsBlockEntryCreate {
  host_group_id?: string | null;
  domain: string;
  action?: DnsBlockAction;
  expires_at?: string | null;
}

export interface DnsBlockBulkImport {
  host_group_id?: string | null;
  action?: DnsBlockAction;
  domains: string[];
}

export interface DnsBlockBulkImportResult {
  inserted: number;
  skipped: number;
}

// Phase 3 #3.7 — webhook subscriptions ------------------------------

export type WebhookEventType =
  | "alert.opened"
  | "alert.state_changed"
  // Phase 4 #4.1 — emitted when the AI summariser persists a row.
  | "alert.summary_ready"
  | "incident.opened"
  | "incident.resolved"
  | "job.completed"
  | "job.failed"
  | "host.enrolled"
  | "host.disconnected";

export const WEBHOOK_EVENT_TYPES: WebhookEventType[] = [
  "alert.opened",
  "alert.state_changed",
  "alert.summary_ready",
  "incident.opened",
  "incident.resolved",
  "job.completed",
  "job.failed",
  "host.enrolled",
  "host.disconnected",
];

export interface WebhookSubscription {
  id: string;
  name: string;
  url: string;
  event_types: WebhookEventType[];
  enabled: boolean;
  failure_count: number;
  last_delivery_at: string | null;
  last_failure_at: string | null;
  created_at: string;
  updated_at: string;
}

// Phase 3 #3.6 — external case management (Jira + ServiceNow).

export type CaseDestinationKind = "jira" | "servicenow";
export type CaseSyncState = "open" | "in_progress" | "resolved" | "closed" | "failed";

export interface CaseDestination {
  id: string;
  kind: CaseDestinationKind;
  name: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

// Phase 4 #4.5 — deception / honeytokens ----------------------------

export type HoneytokenKind = "creds_in_lsass" | "fake_file" | "fake_regkey";

export interface Honeytoken {
  id: string;
  tenant_id: string;
  host_group_id: string | null;
  kind: HoneytokenKind;
  name: string;
  payload_json: Record<string, unknown>;
  target_path: string | null;
  enabled: boolean;
  deployed_count: number;
  hit_count: number;
  created_at: string;
  updated_at: string;
}

export interface HoneytokenCreate {
  host_group_id?: string | null;
  kind: HoneytokenKind;
  name: string;
  payload_json?: Record<string, unknown>;
  target_path?: string | null;
  enabled?: boolean;
}

export interface HoneytokenUpdate {
  kind?: HoneytokenKind;
  name?: string;
  payload_json?: Record<string, unknown>;
  target_path?: string | null;
  enabled?: boolean;
}

export interface HoneytokenHit {
  id: string;
  honeytoken_id: string;
  host_id: string;
  hit_at: string;
  process_pid: number | null;
  process_executable: string | null;
  alert_id: string | null;
  created_at: string;
}

// Phase 3 #3.10 — device control / USB block policy --------------------

export type DevicePolicyKind = "usb_block" | "usb_read_only" | "usb_allow_only";

export interface DevicePolicy {
  id: string;
  host_group_id: string | null;
  kind: DevicePolicyKind;
  allowed_vendor_ids: string[];
  allowed_product_ids: string[];
  enabled: boolean;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

// Phase 3 #3.3 — agent rollout cohorts.
export type RolloutStatus = "pending" | "in_flight" | "success" | "failed" | "rolled_back";

export interface RolloutEvent {
  id: string;
  host_id: string;
  policy_id: string;
  cohort: string;
  version_from: string | null;
  version_to: string;
  status: RolloutStatus;
  error: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface CohortCounts {
  cohort: string;
  success: number;
  failed: number;
  in_flight: number;
}

export interface PolicyRolloutOut {
  policy_id: string;
  policy_name: string;
  rollout_cohort: string | null;
  cohort_target_version: string | null;
  cohort_rolled_out_pct: number;
  cohorts: CohortCounts[];
  recent: RolloutEvent[];
}

export interface Policy {
  id: string;
  name: string;
  description: string | null;
  version: number;
  rollout_cohort: string | null;
  cohort_target_version: string | null;
  cohort_rolled_out_pct: number;
}

// Phase 3 #3.4 — operator-authored dashboards. The widget union here
// mirrors `app/schemas/dashboard.py::Widget`; new widget kinds get
// added to both sides.
export type KpiQuery =
  | "alerts_open"
  | "alerts_today"
  | "hosts_online"
  | "hosts_total"
  | "jobs_failed_24h"
  | "avg_mttr_hours";

export type WidgetType =
  | "kpi"
  | "severity_donut"
  | "state_donut"
  | "host_status_donut"
  | "top_rules"
  | "timeline_24h"
  | "hosts_table"
  | "incidents_table"
  // Phase 4 #4.1 — AI summary card on the alert detail page. Not a
  // dashboard tile; reuses the widget switch so the renderer stays
  // single-source.
  | "ai_summary";

export interface WidgetPosition {
  x: number;
  y: number;
  w: number;
  h: number;
}

interface WidgetBase {
  position: WidgetPosition;
  options?: Record<string, unknown> | null;
}

export interface KpiWidget extends WidgetBase {
  type: "kpi";
  title: string;
  query: KpiQuery;
}

export interface SeverityDonutWidget extends WidgetBase {
  type: "severity_donut";
}

export interface StateDonutWidget extends WidgetBase {
  type: "state_donut";
}

export interface HostStatusDonutWidget extends WidgetBase {
  type: "host_status_donut";
}

export interface TopRulesWidget extends WidgetBase {
  type: "top_rules";
  limit: number;
}

export interface Timeline24hWidget extends WidgetBase {
  type: "timeline_24h";
}

export interface HostsTableWidget extends WidgetBase {
  type: "hosts_table";
  limit: number;
}

export interface IncidentsTableWidget extends WidgetBase {
  type: "incidents_table";
  limit: number;
}

// Phase 4 #4.1 — AI summary card. Not a dashboard tile; the
// AlertDetail page constructs one inline with the alert id pinned
// via `options.alert_id` so the WidgetRenderer can dispatch to the
// same surface the dashboards machinery uses.
export interface AiSummaryWidget extends WidgetBase {
  type: "ai_summary";
  options?: { alert_id?: string } & Record<string, unknown>;
}

export type Widget =
  | KpiWidget
  | SeverityDonutWidget
  | StateDonutWidget
  | HostStatusDonutWidget
  | TopRulesWidget
  | Timeline24hWidget
  | HostsTableWidget
  | IncidentsTableWidget
  | AiSummaryWidget;

export interface Dashboard {
  id: string;
  owner_user_id: string;
  name: string;
  description: string | null;
  shared: boolean;
  is_default: boolean;
  widgets_json: Widget[];
  created_at: string;
  updated_at: string;
}

// Create response also carries the freshly-minted signing secret —
// shown exactly once, never returned again.
export interface WebhookSubscriptionCreateResponse extends WebhookSubscription {
  secret: string;
}

export interface WebhookSubscriptionCreate {
  name: string;
  url: string;
  event_types: WebhookEventType[];
  enabled?: boolean;
}

export interface WebhookSubscriptionUpdate {
  name?: string;
  url?: string;
  event_types?: WebhookEventType[];
  enabled?: boolean;
}

export interface WebhookDelivery {
  id: string;
  subscription_id: string;
  event_type: string;
  payload_json: Record<string, unknown>;
  status: "pending" | "delivered" | "failed" | "disabled";
  attempts: number;
  response_status: number | null;
  response_body_truncated: string | null;
  delivered_at: string | null;
  created_at: string;
}

export interface WebhookDeliveryPage {
  items: WebhookDelivery[];
  total: number;
  limit: number;
  offset: number;
}

export interface CaseDestinationCreate {
  kind: CaseDestinationKind;
  name: string;
  /** Per-kind config dict. Jira requires base_url/email/api_token/project_key;
   * ServiceNow requires instance_url/username/password. */
  config: Record<string, unknown>;
  enabled?: boolean;
}

export interface CaseDestinationUpdate {
  name?: string;
  /** Replaces the entire stored blob; we don't store plaintext so we
   * can't merge partials. */
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export interface CaseLink {
  destination_id: string;
  destination_name: string;
  external_id: string;
  external_url: string | null;
  sync_state: CaseSyncState;
  last_synced_at?: string | null;
  error?: string | null;
}

export interface CaseDestinationTestResult {
  ok: boolean;
  external_id?: string | null;
  external_url?: string | null;
  error?: string | null;
}

export interface DevicePolicyCreate {
  host_group_id?: string | null;
  kind: DevicePolicyKind;
  name: string;
  description?: string | null;
  allowed_vendor_ids?: string[];
  allowed_product_ids?: string[];
  enabled?: boolean;
}

export interface DevicePolicyUpdate {
  kind?: DevicePolicyKind;
  name?: string;
  description?: string | null;
  allowed_vendor_ids?: string[];
  allowed_product_ids?: string[];
  enabled?: boolean;
}

export interface DashboardCreate {
  name: string;
  description?: string | null;
  shared?: boolean;
  widgets_json?: Widget[];
}

export interface DashboardUpdate {
  name?: string;
  description?: string | null;
  shared?: boolean;
  is_default?: boolean;
  widgets_json?: Widget[];
}

/** One resolved widget entry from `GET /api/dashboards/:id/data`.
 * `data` is whatever the per-type resolver returned — the renderer
 * dispatches on `type` and knows what shape to expect. */
export interface WidgetData {
  type: WidgetType | string;
  data: unknown;
  error: string | null;
}

// Phase 4 #4.4 — network sandbox / detonation.

export type DetonationProviderKind = "cuckoo" | "vmray" | "anyrun";
export type DetonationJobStatus = "queued" | "running" | "verdict" | "failed";

export interface DetonationProvider {
  id: string;
  kind: DetonationProviderKind;
  name: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DetonationProviderCreate {
  kind: DetonationProviderKind;
  name: string;
  /** Cuckoo requires `base_url` and accepts an optional `api_token`.
   *  VMRay + ANY.RUN are stubs — config is stored but submits raise
   *  NotImplementedError until an operator wires a real client. */
  config: Record<string, unknown>;
  enabled?: boolean;
}

export interface DetonationProviderUpdate {
  name?: string;
  /** Replaces the entire stored blob; we don't store plaintext so
   * partial merges aren't possible. */
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export interface DetonationJob {
  id: string;
  provider_id: string;
  sha256: string;
  status: DetonationJobStatus;
  verdict_score: number | null;
  verdict_label: string | null;
  external_id: string | null;
  error: string | null;
  submitted_at: string;
  finished_at: string | null;
}

// Phase 4 #4.1 — AI-assisted analyst surfaces ------------------------

/** One suggested response action from the model. The widget renders
 * entries with a known `kind` and ignores anything else, so the
 * vocabulary can grow without a schema change. */
export interface AiSuggestedResponse {
  kind: string;
  label: string;
  rationale?: string | null;
}

export interface AlertSummary {
  id: string;
  alert_id: string;
  tenant_id: string;
  summary: string;
  suggested_response_json: AiSuggestedResponse[] | null;
  model_id: string;
  cached_input_tokens: number;
  output_tokens: number;
  created_at: string;
}

export interface NlQueryRequest {
  prompt: string;
  language: "kql" | "lucene";
}

export interface NlQueryResponse {
  query: string;
  language: "kql" | "lucene";
  cached_input_tokens: number;
  output_tokens: number;
  model_id: string;
}
