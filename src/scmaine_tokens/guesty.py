"""Guesty token broker. 5-OAuth-tokens-per-24h limit upstream."""

import os
import time
from typing import Optional, Tuple

import httpx

from scmaine_tokens._cache import FileCache, _resolve_cache_dir
from scmaine_tokens.errors import ConfigurationError, RateLimitedError, TokenFetchError

_TOKEN_URL = "https://open-api.guesty.com/oauth2/token"
# Refresh 30 minutes before expiry to avoid mid-request expiry.
_REFRESH_BUFFER_S = 30 * 60
_DEFAULT_TTL_S = 24 * 3600


def get_guesty_token(
    *,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    cache_path: Optional[object] = None,  # pathlib.Path or None
    now: Optional[float] = None,           # time.time() override for tests
    http_client_factory=None,              # callable returning an httpx.Client
) -> str:
    """Return a fresh Guesty OAuth access_token, refreshing only when needed.

    Reads GUESTY_CLIENT_ID / GUESTY_CLIENT_SECRET from env if not supplied.
    Caches at ~/.cache/scmaine-tokens/guesty.json (override via
    SCMAINE_TOKENS_CACHE_DIR or by passing cache_path explicitly).

    Guesty enforces a hard limit of 5 OAuth token requests per 24 hours per
    client_id. This broker prevents multiple tools from independently hitting
    that limit by sharing one cached token.
    """
    cid = client_id or os.environ.get("GUESTY_CLIENT_ID")
    csec = client_secret or os.environ.get("GUESTY_CLIENT_SECRET")
    if not cid or not csec:
        raise ConfigurationError(
            "GUESTY_CLIENT_ID and GUESTY_CLIENT_SECRET must be set "
            "(env vars or kwargs)."
        )

    if cache_path is None:
        cache_path = _resolve_cache_dir() / "guesty.json"

    import pathlib
    cache = FileCache(pathlib.Path(cache_path))
    now_ts = now() if callable(now) else (now if now is not None else time.time())

    with cache.lock():
        cached = cache.read()
        if cached:
            access_token = cached.get("access_token", "")
            expires_at = cached.get("expires_at", 0)
            if access_token and (expires_at - now_ts) > _REFRESH_BUFFER_S:
                return access_token

        # Need a new token.
        access_token, expires_in = _fetch_token(cid, csec, http_client_factory)
        cache.write({
            "access_token": access_token,
            "expires_at": now_ts + expires_in,
            "fetched_at": now_ts,
            "client_id": cid,  # for debugging — not the secret
        })
        return access_token


def _fetch_token(
    client_id: str,
    client_secret: str,
    http_client_factory=None,
) -> Tuple[str, int]:
    """POST to Guesty's token endpoint. Returns (access_token, expires_in_seconds)."""
    factory = http_client_factory or (lambda: httpx.Client(timeout=30.0))
    with factory() as client:
        resp = client.post(
            _TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "scope": "open-api",
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
    if resp.status_code == 429:
        raise RateLimitedError(
            "Guesty token rate-limited (429). All 5 tokens for the 24h "
            "window may already be in use."
        )
    if resp.status_code != 200:
        # Redact response body — error responses from token endpoints
        # occasionally echo input or partial data; never include raw text in
        # exception messages that may end up in logs / Sentry / CI output.
        raise TokenFetchError(
            f"Guesty token fetch failed (status={resp.status_code}). "
            f"Response body redacted (length={len(resp.text)} chars)."
        )
    try:
        data = resp.json()
    except (ValueError, TypeError):
        raise TokenFetchError(
            "Guesty token response was not valid JSON (body redacted)."
        )
    if not isinstance(data, dict):
        raise TokenFetchError("Guesty token response was not a JSON object.")
    if "access_token" not in data:
        # Surface keys (without values) for debugging; never the values.
        raise TokenFetchError(
            f"Guesty token response missing access_token. "
            f"Response keys: {sorted(data.keys())} (values redacted)."
        )
    return data["access_token"], int(data.get("expires_in", _DEFAULT_TTL_S))
