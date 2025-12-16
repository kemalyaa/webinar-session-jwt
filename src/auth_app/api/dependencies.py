from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_app.core.config import settings
from auth_app.core.db import SessionLocal, get_session
from auth_app.core.db_manager import DBManager
from auth_app.domain.models import User, UserSession
from auth_app.core.security import security
from auth_app.core.tokens import tokens


SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_db_manager() -> DBManager:
    async with DBManager(SessionLocal) as manager:
        yield manager


DBManagerDep = Annotated[DBManager, Depends(get_db_manager)]


async def get_current_user_from_bearer(request: Request, session: SessionDep) -> User:
    raw_token = _extract_access_token(request)
    try:
        payload = tokens.decode_token(raw_token, expected_type="access")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired") from None
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from None
    user_id = int(payload["sub"])
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user


async def get_current_user_from_session(
    request: Request, session: SessionDep
) -> User:
    token_hash = _get_session_token_hash(request)
    stored_session = await _find_session(session, token_hash)
    now = datetime.now(timezone.utc)
    absolute_expires_at = await _ensure_not_absolute_expired(session, stored_session, now)
    await _extend_if_needed(session, stored_session, now, absolute_expires_at)
    await _check_expiry(session, stored_session, now)
    user = await _get_session_user(session, stored_session)
    return user


def _get_session_token_hash(request: Request) -> str:
    raw_token = request.cookies.get(settings.session_cookie_name)
    if not raw_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "No session cookie")
    return tokens.hash_session_token(raw_token)


async def _find_session(session: SessionDep, token_hash: str) -> UserSession:
    stmt = select(UserSession).where(UserSession.token_hash == token_hash)
    stored_session = await session.scalar(stmt)
    if not stored_session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session not found")
    return stored_session


def _absolute_deadline(stored_session: UserSession) -> datetime:
    return stored_session.created_at + timedelta(days=settings.session_absolute_timeout_days)


async def _ensure_not_absolute_expired(
    session: SessionDep, stored_session: UserSession, now: datetime
) -> datetime:
    absolute_expires_at = _absolute_deadline(stored_session)
    if now >= absolute_expires_at:
        await _expire_session(session, stored_session, "Session expired")
    return absolute_expires_at


async def _extend_if_needed(
    session: SessionDep, stored_session: UserSession, now: datetime, absolute_expires_at: datetime
) -> None:
    if (now - stored_session.last_refreshed_at) >= timedelta(minutes=settings.session_rolling_interval_minutes):
        new_expiry = now + timedelta(minutes=settings.session_extend_minutes)
        stored_session.expires_at = min(new_expiry, absolute_expires_at)
        stored_session.last_refreshed_at = now
        await session.commit()


async def _check_expiry(session: SessionDep, stored_session: UserSession, now: datetime) -> None:
    if stored_session.expires_at <= now:
        await _expire_session(session, stored_session, "Session expired")


async def _get_session_user(session: SessionDep, stored_session: UserSession) -> User:
    user = await session.get(User, stored_session.user_id)
    if not user:
        await _expire_session(session, stored_session, "User not found")
    return user


async def _expire_session(session: SessionDep, stored_session: UserSession, message: str) -> None:
    await session.delete(stored_session)
    await session.commit()
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, message)


def _extract_access_token(request: Request) -> str:
    header = request.headers.get("authorization")
    if header and header.lower().startswith("bearer "):
        return header.split(" ", 1)[1].strip()
    cookie_token = request.cookies.get(settings.access_cookie_name)
    if cookie_token:
        return cookie_token
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing access token")
