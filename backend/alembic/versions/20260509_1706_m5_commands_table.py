"""M5: commands table

Adds the `commands` table that the REST API populates with response
actions (kill / block / unblock) and the gRPC HostStream dispatches
to agents.

Revision ID: 15fc3fa55e1f
Revises: 20260508_1700
Create Date: 2026-05-09
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = '15fc3fa55e1f'
down_revision: str | None = '20260508_1700'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'commands',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('host_id', sa.Uuid(), nullable=False),
        sa.Column(
            'kind',
            sa.Enum(
                'kill_process', 'block_process', 'block_file',
                'unblock_process', 'unblock_file',
                name='command_kind',
            ),
            nullable=False,
        ),
        sa.Column(
            'status',
            sa.Enum('pending', 'dispatched', 'succeeded', 'failed', name='command_status'),
            nullable=False,
        ),
        sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('triggered_by_alert_id', sa.Uuid(), nullable=True),
        sa.Column('triggered_by_rule_id', sa.Uuid(), nullable=True),
        sa.Column('issued_by_user_id', sa.Uuid(), nullable=True),
        sa.Column('dispatched_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error', sa.String(length=512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], name=op.f('fk_commands_host_id_hosts'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['issued_by_user_id'], ['users.id'], name=op.f('fk_commands_issued_by_user_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['triggered_by_alert_id'], ['alerts.id'], name=op.f('fk_commands_triggered_by_alert_id_alerts'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['triggered_by_rule_id'], ['rules.id'], name=op.f('fk_commands_triggered_by_rule_id_rules'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_commands')),
    )
    op.create_index(op.f('ix_commands_host_id'), 'commands', ['host_id'], unique=False)
    op.create_index(op.f('ix_commands_status'), 'commands', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_commands_status'), table_name='commands')
    op.drop_index(op.f('ix_commands_host_id'), table_name='commands')
    op.drop_table('commands')
    op.execute('DROP TYPE IF EXISTS command_kind')
    op.execute('DROP TYPE IF EXISTS command_status')
