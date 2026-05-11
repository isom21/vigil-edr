"""Centralized settings. Loaded from environment / .env file.

Subsystems should depend on `settings` from here, never read os.environ directly.
"""

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
    pg_dsn: str = "postgresql+asyncpg://edr:vigil_dev_password@localhost:5432/edr"

    # OpenSearch
    opensearch_url: str = "http://localhost:9200"

    # Kafka
    kafka_brokers: str = "localhost:19092"
    topic_telemetry_raw: str = "telemetry.raw"
    topic_telemetry_normalized: str = "telemetry.normalized"
    topic_alerts_raw: str = "alerts.raw"
    topic_agent_commands: str = "agent.commands"

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
    # manager holds the long-lived creds; agents and analysts only ever
    # see short-lived presigned URLs.
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "vigil"
    minio_secret_key: str = "vigil_dev_password"
    minio_secure: bool = False
    minio_bucket_artifacts: str = "vigil-artifacts"
    minio_bucket_snapshots: str = "vigil-snapshots-raw"
    # Presigned URL TTLs. PUT is given to agents on job dispatch; GET
    # is handed to analysts on download click. Keep both short.
    minio_presign_put_ttl_seconds: int = 900
    minio_presign_get_ttl_seconds: int = 600


settings = Settings()
