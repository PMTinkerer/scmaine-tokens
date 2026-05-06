"""Breezeway token broker. 1-req/min auth rate limit upstream.

Breezeway auth returns access_token + refresh_token as JWTs. There is no
explicit ``expires_in`` field in the API response — expiry is encoded in the
JWT ``exp`` claim. Falls back to 24h / 30d defaults if JWT parsing fails.
"""

import base64
import json
import logging
import os
import pathlib
import time
from typing import Optional, Tuple

import httpx

from scmaine_tokens._cache import FileCache, _resolve_cache_dir
from scmaine_tokens.errors import ConfigurationError, RateLimitedError, TokenFetchError

logger = logging.getLogger(__name__)

_AUTH_URL = "https://api.breezeway.io/public/auth/v1/"
_REFRESH_URL = "https://api.breezeway.io/public/auth/v1/refresh"

# Refresh 30 minutes before expiry to avoid mid-request expiry.
_REFRESH_BUFFER_S = 30 * 60

# Fallback TTLs if JWT exp parsing fails (observed from live API).
_DEFAULT_ACCESS_EXPIRES_IN = 86_400       # 24 hours
_DEFAULT_REFRESH_EXPIRES_IN = 2_592_000   # 30 days


def _jwt_seconds_until_exp(token: str, default: int) -> int:
    """Decode a JWT's exp claim and return seconds-until-expiry.

    Returns the supplied ``default`` if the token is not a parseable JWT.
    No signature verification — we trust this token because we just minted it.
    """
    try:
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        exp = int(claims["exp"])
        remaining = exp - int(time.time())
        return remaining if remaining > 0 else default
    except (IndexError, KeyError, ValueError, json.JSONDecodeError):
        return default


def get_breezeway_token(
    *,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    cache_path: Optional[object] = None,  # pathlib.Path or None
    now: Optional[float] = None,           # time.time() override for tests
    http_client_factory=None,              # callable returning an httpx.Client
) -> str:
    """Return a fresh Breezeway access_token. Uses the cached refresh_token
    when access has expired; full re-auth when the refresh token has expired.

    Reads BREEZEWAY_CLIENT_ID / BREEZEWAY_CLIENT_SECRET from env if not
    supplied. Caches at ~/.cache/scmaine-tokens/breezeway.json (override via
    SCMAINE_TOKENS_CACHE_DIR or by passing cache_path explicitly).

    Breezeway enforces ~1 auth request per minute. This broker prevents
    multiple tools from independently hitting that limit.
    """
    cid = client_id or os.environ.get("BREEZEWAY_CLIENT_ID")
    csec = client_secret or os.environ.get("BREEZEWAY_CLIENT_SECRET")
    if not cid or not csec:
        raise ConfigurationError(
            "BREEZEWAY_CLIENT_ID and BREEZEWAY_CLIENT_SECRET must be set "
            "(env vars or kwargs)."
        )

    if cache_path is None:
        cache_path = _resolve_cache_dir() / "breezeway.json"

    cache = FileCache(pathlib.Path(cache_path))
    now_ts = now() if callable(now) else (now if now is not None else time.time())

    with cache.lock():
        cached = cache.read()
        if cached:
            access_token = cached.get("access_token", "")
            access_expires_at = cached.get("access_expires_at", 0)
            refresh_token = cached.get("refresh_token", "")
            refresh_expires_at = cached.get("refresh_expires_at", 0)

            # 1. Access token still fresh — return it directly.
            if access_token and (access_expires_at - now_ts) > _REFRESH_BUFFER_S:
                return access_token

            # 2. Access expired but refresh token still fresh — try it.
            #    The cached `refresh_expires_at` is optimistic: Breezeway can
            #    revoke or rotate a refresh token before its JWT exp, and
            #    historically has. If the refresh attempt fails (typically
            #    401, but any TokenFetchError counts), we MUST fall through
            #    to full re-auth below — otherwise the broker enters a
            #    permanent failure loop until refresh_expires_at finally
            #    elapses (potentially 30 days from now). client_credentials
            #    is the canonical recovery path. See test
            #    `test_refresh_401_falls_back_to_full_auth`.
            if refresh_token and (refresh_expires_at - now_ts) > _REFRESH_BUFFER_S:
                try:
                    new_access, new_refresh, access_ttl, refresh_ttl = _refresh_auth(
                        refresh_token, http_client_factory
                    )
                except TokenFetchError as exc:
                    logger.warning(
                        "Breezeway refresh-token call failed (%s); falling "
                        "back to client_credentials full re-auth.",
                        exc,
                    )
                    # Drop the stale refresh token so we don't try it again
                    # if full_auth itself transiently fails — the next call
                    # will start fresh.
                    cache.write({
                        "access_token": "",
                        "refresh_token": "",
                        "access_expires_at": 0,
                        "refresh_expires_at": 0,
                        "fetched_at": now_ts,
                    })
                else:
                    cache.write({
                        "access_token": new_access,
                        "refresh_token": new_refresh,
                        "access_expires_at": now_ts + access_ttl,
                        "refresh_expires_at": now_ts + refresh_ttl,
                        "fetched_at": now_ts,
                    })
                    return new_access

        # 3. No valid cache, both tokens expired, OR refresh just failed — full re-auth.
        access_token, refresh_token, access_ttl, refresh_ttl = _full_auth(
            cid, csec, http_client_factory
        )
        cache.write({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_expires_at": now_ts + access_ttl,
            "refresh_expires_at": now_ts + refresh_ttl,
            "fetched_at": now_ts,
        })
        return access_token


def _full_auth(
    client_id: str,
    client_secret: str,
    http_client_factory=None,
) -> Tuple[str, str, int, int]:
    """POST to /auth/v1/ with client credentials.

    Returns (access_token, refresh_token, access_ttl_s, refresh_ttl_s).
    """
    factory = http_client_factory or (lambda: httpx.Client(timeout=30.0))
    with factory() as client:
        resp = client.post(
            _AUTH_URL,
            json={
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
    return _parse_auth_response(resp)


def _refresh_auth(
    refresh_token: str,
    http_client_factory=None,
) -> Tuple[str, str, int, int]:
    """POST to /auth/v1/refresh with a valid refresh_token.

    Returns (access_token, refresh_token, access_ttl_s, refresh_ttl_s).
    """
    factory = http_client_factory or (lambda: httpx.Client(timeout=30.0))
    with factory() as client:
        resp = client.post(
            _REFRESH_URL,
            json={"refresh_token": refresh_token},
        )
    return _parse_auth_response(resp)


def _parse_auth_response(resp: httpx.Response) -> Tuple[str, str, int, int]:
    """Parse a Breezeway auth response. Raises on error."""
    if resp.status_code == 429:
        raise RateLimitedError(
            "Breezeway auth rate-limited (429). Breezeway enforces ~1 auth "
            "request per minute."
        )
    if resp.status_code not in (200, 201):
        # Redact response body — never include raw upstream text in
        # exceptions that may surface in logs / Sentry / CI output.
        raise TokenFetchError(
            f"Breezeway auth failed (status={resp.status_code}). "
            f"Response body redacted (length={len(resp.text)} chars)."
        )
    try:
        data = resp.json()
    except (ValueError, TypeError):
        raise TokenFetchError(
            "Breezeway auth response was not valid JSON (body redacted)."
        )
    if not isinstance(data, dict):
        raise TokenFetchError("Breezeway auth response was not a JSON object.")
    if "access_token" not in data or "refresh_token" not in data:
        raise TokenFetchError(
            f"Breezeway auth response missing access_token/refresh_token. "
            f"Response keys: {sorted(data.keys())} (values redacted)."
        )
    access = data["access_token"]
    refresh = data["refresh_token"]
    access_ttl = (
        int(data["expires_in"])
        if "expires_in" in data
        else _jwt_seconds_until_exp(access, _DEFAULT_ACCESS_EXPIRES_IN)
    )
    refresh_ttl = (
        int(data["refresh_expires_in"])
        if "refresh_expires_in" in data
        else _jwt_seconds_until_exp(refresh, _DEFAULT_REFRESH_EXPIRES_IN)
    )
    return access, refresh, access_ttl, refresh_ttl
