"""Centralized settings. Loaded from environment / .env file.

Subsystems should depend on `settings` from here, never read os.environ directly.
"""

import os

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="VIGIL_",
        extra="ignore",
    )

    debug: bool = False

    # Postgres
    pg_dsn: str = "postgresql+asyncpg://vigil_manager:vigil_dev_password@localhost:5432/vigil"
    # Owner-role DSN for audit_log. After M16.a (fixed), audit_log is
    # owned by `vigil_audit_writer` and the runtime user `vigil_manager`
    # keeps only SELECT + INSERT. Audit schema migrations and the chain
    # verifier connect through this DSN so they have the privileges
    # they need without granting the runtime pool a path to mutate
    # the log. Defaults to `pg_dsn` so dev environments that haven't
    # run install.sh yet still work for reads; production must set
    # this explicitly.
    pg_dsn_audit: str = ""

    # OpenSearch
    opensearch_url: str = "http://localhost:9200"

    # Kafka
    kafka_brokers: str = "localhost:19092"
    topic_telemetry_raw: str = "telemetry.raw"
    topic_telemetry_normalized: str = "telemetry.normalized"
    topic_alerts_raw: str = "alerts.raw"
    topic_agent_commands: str = "agent.commands"
    # Phase 2 #2.4: auth event fan-out. The gRPC ingest path mirrors any
    # EndpointEvent whose payload is AuthEvent onto this topic so the
    # auth-focused workers (UEBA, brute-force detector) can subscribe
    # without re-parsing the firehose.
    topic_auth: str = "telemetry.auth"

    # Auth
    jwt_secret: str = Field(default="dev-only-change-me", min_length=16)
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_minutes: int = 60
    jwt_refresh_ttl_days: int = 14

    # Internal CA (encrypted at rest with this master key in dev)
    ca_master_key: str = Field(default="dev-only-change-me-32-bytes-long!!", min_length=32)

    # gRPC ingest
    grpc_listen: str = "0.0.0.0:50051"
    grpc_tls_cert: str = "./certs/server.crt"
    grpc_tls_key: str = "./certs/server.key"
    # Comma-separated extra SAN entries for the manager's gRPC server cert.
    # IP literals are added as IP SANs; everything else as DNS SANs. Use this
    # for the address agents actually dial (e.g. Tailscale MagicDNS name +
    # tailnet IP) when it differs from socket.gethostname().
    grpc_san_extras: str = ""

    # Per-minute rate limits per role. Anon covers anything before auth
    # (login, agent enrollment).
    rl_user_admin_per_min: int = 600
    rl_user_analyst_per_min: int = 300
    rl_user_viewer_per_min: int = 120
    rl_api_token_per_min: int = 600
    rl_anon_per_min: int = 60

    # MinIO (S3-compatible) object store for the Jobs engine. The
    # manager holds the long-lived creds; agents and analysts hit the
    # manager's reverse proxy at /api/uploads + /api/downloads and the
    # manager forwards to MinIO server-side. Agents never see MinIO
    # directly, which means the only port that needs to be reachable
    # cross-network is the manager's REST listener.
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "vigil"
    minio_secret_key: str = "vigil_dev_password"
    minio_secure: bool = False
    minio_bucket_artifacts: str = "vigil-artifacts"
    minio_bucket_snapshots: str = "vigil-snapshots-raw"
    # M23.a leftover — kept so callers that still hand out direct
    # presigned MinIO URLs (none in production) don't break. The Jobs
    # engine ignores these now.
    minio_presign_put_ttl_seconds: int = 900
    minio_presign_get_ttl_seconds: int = 600

    # Public URL of the manager's REST listener. The presigned-upload
    # URLs the manager hands to agents are built off this; same for
    # the artifact download links analysts hit from the UI. Must be
    # reachable from agent and analyst networks.
    manager_public_url: str = "http://localhost:8000"
    # Upload-token TTL (seconds). Bound to a specific bucket/key so a
    # leaked token can only overwrite that one object before it
    # expires.
    upload_token_ttl_seconds: int = 900
    # Independent HMAC key for the per-upload grant tokens (review
    # MEDIUM #18). Previously the agent upload-grant HMAC and the
    # session JWT signing shared `jwt_secret` — compromise of one
    # was compromise of both. `install.sh` generates a separate
    # 32-byte hex value; in dev it falls back to `jwt_secret` so
    # local environments keep working without a fresh `.env`.
    upload_token_key: str = ""
    # Per-upload size cap. host_sweep artifacts are typically <1 MiB;
    # acquisition jobs (file_acquire, memory_dump) can push this. The
    # manager rejects anything larger at the proxy layer.
    upload_max_bytes: int = 512 * 1024 * 1024  # 512 MiB

    # Fernet key (URL-safe base64-encoded 32 bytes) used to encrypt
    # users' TOTP secrets at rest. Kept separate from jwt_secret /
    # upload_token_key so compromise of one auth path doesn't unlock
    # the others. `install.sh` generates a fresh value; in dev it
    # falls back to a deterministic dev string so local environments
    # keep working without a fresh `.env`.
    totp_encryption_key: str = ""

    # Optional Redis URL backing the HA primitives (rate limit, alert
    # broker pub/sub, login-failure throttle). Empty string is the
    # single-instance default: every primitive uses its in-process
    # implementation. Set to e.g. `redis://localhost:6379/0` to share
    # state across multiple manager instances. Not a secret — no
    # production refuse-to-boot guard. See `app/core/redis_client.py`.
    redis_url: str = ""

    # Phase 1 #1.10 alert deduplication window (seconds).
    alert_dedup_window_s: int = 300

    # Phase 1 #1.4 — live-response remote shell.
    terminal_idle_s: int = 300
    terminal_audit_batch_bytes: int = 4096
    terminal_audit_batch_s: int = 5

    # Phase 1 #1.11 — incident grouper.
    incident_window_s: int = 600
    incident_grouper_interval_s: int = 60

    # Phase 1 #1.9: threat-intel feed ingest.
    intel_ingest_interval_s: int = 60
    intel_encryption_key: str = ""

    # Phase 1 #1.5 + #1.7: Fernet key for SIEM destinations + routing channels.
    notification_encryption_key: str = ""

    # Phase 2 #2.11: threat-hunting workbench. `hunt_result_limit`
    # caps the OpenSearch `size` per hunt run; `hunt_scheduler_interval_s`
    # gates the scheduler worker's outer tick (floor 10 s).
    hunt_result_limit: int = 10_000
    hunt_scheduler_interval_s: int = 60

    # Phase 2 #2.6: cross-process correlation graph store. The indexer
    # tails telemetry.normalized and persists process_started/exited
    # into the `process_chain` table. Set the indexer flag to "0" in
    # environments without Kafka (tests, single-tenant). Retention
    # bounds the table by `started_at`; long-running processes that
    # started before the cutoff are purged.
    process_chain_indexer_enabled: str = "1"
    process_chain_retention_days: int = 90

    # Phase 2 #2.3: sequence / behavioral rules engine.
    sequence_detector_enabled: bool = True
    sequence_rule_default_window_s: int = 60

    # Phase 1 #1.6: OIDC SSO.
    oidc_enabled: bool = False
    oidc_issuer_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://localhost:8000/api/auth/oidc/callback"
    oidc_default_role: str = "viewer"

    # Phase 2 #2.8: application allowlist learner. Set to "0" to keep
    # the worker dormant on this manager instance (useful when running
    # multiple managers and only one should drive the learner loop —
    # the in-process staging queue isn't shared across processes).
    allowlist_learner_enabled: str = "1"

    # Phase 3 #3.3: agent rollout cohorts. The seed buckets each host
    # into [0, 99]; changing it re-rolls the bucketing fleet-wide
    # (useful when a canary keeps landing on the same hosts). The
    # failure threshold + window let the rollout monitor trip the
    # breaker — N failed events within W seconds drops the policy's
    # ``cohort_rolled_out_pct`` to 0. Monitor interval gates the tick
    # of the worker loop (floor 5 s).
    rollout_failure_threshold: int = 3
    rollout_failure_window_s: int = 600
    rollout_monitor_interval_s: int = 30
    rollout_cohort_seed: str = "vigil-cohort-v1"

    # Phase 2 #2.7: NVD-driven vulnerability assessment. `nvd_api_key`
    # is optional — empty string keeps the worker on the 6s public
    # rate-limit floor; setting a key drops that to 0.6s per request.
    # `vuln_scan_interval_s` gates the worker tick (daily by default —
    # NVD's recommended cadence). `nvd_base_url` is overridable for
    # tests and for operators routing through an internal mirror.
    nvd_api_key: str = ""
    vuln_scan_interval_s: int = 86400
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json"


settings = Settings()


# Refuse-to-boot guard: in production (`debug=False`), the crypto
# secrets MUST be rotated off their dev defaults. Otherwise we'd
# boot advertising tamper-evidence + JWT signing + CA encryption +
# 2FA-secret encryption + per-upload HMAC that don't actually
# stand up to scrutiny. `install.sh` rotates all of them; operators
# that build from compose alone must set them in `.env` or the
# manager's process environment before starting.
JWT_SECRET_DEV_DEFAULT = "dev-only-change-me"
CA_MASTER_KEY_DEV_PREFIX = "dev-only-"
# Deterministic Fernet key used as a fallback in dev environments
# that haven't run `install.sh`. Production refuses to boot with this
# value (see `assert_production_secrets`). Generated once via
# base64.urlsafe_b64encode(b"dev-only-vigil-totp-key-32bytes!").
TOTP_KEY_DEV_DEFAULT = "ZGV2LW9ubHktdmlnaWwtdG90cC1rZXktMzJieXRlcyE="
# Phase 1 #1.9: dev-default Fernet key for `intel_encryption_key`.
INTEL_KEY_DEV_DEFAULT = "ZGV2LW9ubHktdmlnaWwtaW50ZWwta2V5LTMyYnl0ZXM="
# Phase 1 #1.5 + #1.7: dev-default Fernet key for `notification_encryption_key`.
NOTIFICATION_KEY_DEV_DEFAULT = "ZGV2LW9ubHktdmlnaWwtbm90aWYta2V5LTMyYnl0ZXM="


class DevSecretsInProductionError(RuntimeError):
    """The manager was started with debug=False but one or more crypto
    secrets still equal their dev defaults / are unset."""


def assert_production_secrets(s: Settings | None = None) -> None:
    """Raise DevSecretsInProductionError if any crypto secret is still at
    its dev default while debug=False. Called from the lifespan before
    we open any subsystems."""
    s = s or settings
    if s.debug:
        return
    problems: list[str] = []
    if s.jwt_secret == JWT_SECRET_DEV_DEFAULT:
        problems.append("VIGIL_JWT_SECRET is still the dev default")
    if s.ca_master_key.startswith(CA_MASTER_KEY_DEV_PREFIX):
        problems.append("VIGIL_CA_MASTER_KEY is still the dev default")
    if not os.environ.get("VIGIL_AUDIT_HMAC_KEY"):
        problems.append("VIGIL_AUDIT_HMAC_KEY is unset (audit chain would be dormant)")
    if not s.totp_encryption_key or s.totp_encryption_key == TOTP_KEY_DEV_DEFAULT:
        problems.append("VIGIL_TOTP_ENCRYPTION_KEY is unset or still the dev default")
    if not s.intel_encryption_key or s.intel_encryption_key == INTEL_KEY_DEV_DEFAULT:
        problems.append("VIGIL_INTEL_ENCRYPTION_KEY is unset or still the dev default")
    if (
        not s.notification_encryption_key
        or s.notification_encryption_key == NOTIFICATION_KEY_DEV_DEFAULT
    ):
        problems.append("VIGIL_NOTIFICATION_ENCRYPTION_KEY is unset or still the dev default")
    # M18 separated upload_token_key from jwt_secret so a leak of one
    # didn't compromise the other. The empty-string default silently
    # falls back to jwt_secret to keep older dev environments working;
    # production must set the key explicitly or the M18 fix regresses.
    if not s.upload_token_key:
        problems.append(
            "VIGIL_UPLOAD_TOKEN_KEY is unset "
            "(would silently fall back to VIGIL_JWT_SECRET — regresses M18)"
        )
    # Phase 1 #1.6: if OIDC is enabled, the three IdP-side identifiers
    # must all be set. We refuse to boot in production with a half-
    # configured OIDC because the half-broken state would either crash
    # on the first SSO login or — worse — let the password fallback
    # silently mask the misconfiguration.
    if s.oidc_enabled:
        if not s.oidc_issuer_url:
            problems.append("VIGIL_OIDC_ENABLED=True but VIGIL_OIDC_ISSUER_URL is empty")
        if not s.oidc_client_id:
            problems.append("VIGIL_OIDC_ENABLED=True but VIGIL_OIDC_CLIENT_ID is empty")
        if not s.oidc_client_secret:
            problems.append("VIGIL_OIDC_ENABLED=True but VIGIL_OIDC_CLIENT_SECRET is empty")
    if problems:
        raise DevSecretsInProductionError(
            "Refusing to start: production secrets must be rotated. "
            + "; ".join(problems)
            + ". See docs/install.md#crypto-secrets for the install.sh-generated values."
        )
