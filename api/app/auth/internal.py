import hmac

from fastapi import Header, HTTPException, status

from app.config import settings

INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key"


async def verify_internal_api_key(
    x_internal_api_key: str | None = Header(default=None, alias=INTERNAL_API_KEY_HEADER),
) -> None:
    """Guards /internal/* routes, which only the console backend may call."""
    if not x_internal_api_key or not hmac.compare_digest(
        x_internal_api_key, settings.INTERNAL_API_KEY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing internal API key",
        )
