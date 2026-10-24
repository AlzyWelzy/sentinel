import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from app.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Migrations run as the owner role: it owns the tables, so it's the only role
# that can create them, change RLS policies and grant to the other roles.
OWNER_URL = os.environ.get(
    "DATABASE_OWNER_URL", "postgresql+asyncpg://pulsegrid:pulsegrid@localhost:5432/pulsegrid"
)


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(OWNER_URL)
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


asyncio.run(run_migrations_online())
