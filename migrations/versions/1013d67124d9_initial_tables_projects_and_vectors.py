"""Revision ID: 1013d67124d9
Revises: 
Create Date: 2025-05-21 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1013d67124d9'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'projects',
        sa.Column('id', sa.String(length=255), primary_key=True),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.UniqueConstraint('id', name='uq_project_id')
    )
    op.create_table(
        'vectors',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('project_id', sa.String(length=255), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('data', sa.JSON(), nullable=False),
    )

def downgrade():
    op.drop_table('vectors')
    op.drop_table('projects')
