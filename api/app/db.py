from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

app_engine = create_async_engine(settings.DATABASE_APP_URL, pool_pre_ping=True)
service_engine = create_async_engine(settings.DATABASE_SERVICE_URL, pool_pre_ping=True)

AppSession = async_sessionmaker(app_engine, expire_on_commit=False)
ServiceSession = async_sessionmaker(service_engine, expire_on_commit=False)


async def service_session() -> AsyncIterator[AsyncSession]:
    """Cross-tenant session for superadmin routes. Never use it for customer requests."""
    async with ServiceSession() as session, session.begin():
        yield session
