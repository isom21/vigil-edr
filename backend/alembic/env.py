"""Alembic env, sync mode (asyncpg DSN converted to psycopg for migrations)."""
from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Convert async DSN to sync for Alembic migrations.
sync_dsn = settings.pg_dsn.replace("+asyncpg", "+psycopg")
config.set_main_option("sqlalchemy.url", sync_dsn)

# Models import target — populated in M1 once SQLAlchemy models exist.
target_metadata = None


def run_migrations_offline() -> None:
    context.configure(
        url=sync_dsn,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg_section = config.get_section(config.config_ini_section, {})
    cfg_section["sqlalchemy.url"] = sync_dsn
    connectable = engine_from_config(
        cfg_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
