"""Unit tests for breezeway.py."""

import base64
import json
import pathlib
import threading
import time

import pytest

from scmaine_tokens._cache import FileCache
from scmaine_tokens.breezeway import (
    _DEFAULT_ACCESS_EXPIRES_IN,
    _DEFAULT_REFRESH_EXPIRES_IN,
    _jwt_seconds_until_exp,
    get_breezeway_token,
)
from scmaine_tokens.errors import ConfigurationError, RateLimitedError, TokenFetchError


# ---------------------------------------------------------------------------
# JWT test helpers
# ---------------------------------------------------------------------------

def _make_jwt(exp: int) -> str:
    """Build a minimal JWT with the given exp claim (no real signature)."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload_bytes = json.dumps({"exp": exp}).encode()
    payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesignature"


# ---------------------------------------------------------------------------
# Fake httpx plumbing (same pattern as test_guesty.py)
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code: int, body: dict) -> None:
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self) -> dict:
        return self._body


class FakeClient:
    def __init__(self, responses) -> None:
        # responses: a list of FakeResponse, returned in order; last one repeats.
        self._responses = responses
        self.call_count = 0
        self.last_url = None
        self.urls: list = []

    def post(self, url: str, **kwargs):
        self.call_count += 1
        self.last_url = url
        self.urls.append(url)
        idx = min(self.call_count - 1, len(self._responses) - 1)
        return self._responses[idx]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def sequential_factory(responses):
    """Factory that returns a fresh FakeClient per call but shares a counter.

    The broker constructs one client per HTTP call (factory()), so we need
    to cycle through `responses` across multiple factory() invocations,
    not multiple .post() calls on a single client. Tracks all URLs seen.
    """
    state = {"calls": 0, "urls": []}

    def factory():
        idx = state["calls"]
        state["calls"] += 1
        body_idx = min(idx, len(responses) - 1)
        client = FakeClient([responses[body_idx]])
        # Subclass to push URLs into shared state so the test can assert
        # both the refresh URL and the auth URL were both called.
        original_post = client.post

        def post_and_track(url, **kwargs):
            state["urls"].append(url)
            return original_post(url, **kwargs)

        client.post = post_and_track
        return client

    return factory, state


def _ok_body(
    access_token: str = "acc_tok",
    refresh_token: str = "ref_tok",
) -> dict:
    # No expires_in / refresh_expires_in — mirrors live API behaviour.
    return {"access_token": access_token, "refresh_token": refresh_token}


def single_factory(status_code: int = 200, body: dict = None):
    """Return (factory_callable, FakeClient) for a single-response scenario."""
    if body is None:
        body = _ok_body()
    client = FakeClient([FakeResponse(status_code, body)])
    return (lambda: client), client


# ---------------------------------------------------------------------------
# JWT parsing tests
# ---------------------------------------------------------------------------

class TestJwtSecUntilExp:
    @pytest.mark.parametrize("delta,expected_range", [
        (3600, (3590, 3601)),   # 1 hour future
        (86400, (86390, 86401)),  # 24 hours future
    ])
    def test_valid_jwt_returns_remaining_seconds(self, delta, expected_range):
        exp = int(time.time()) + delta
        token = _make_jwt(exp)
        result = _jwt_seconds_until_exp(token, default=9999)
        assert expected_range[0] <= result <= expected_range[1], (
            f"Expected {expected_range}, got {result}"
        )

    def test_already_expired_jwt_returns_default(self):
        exp = int(time.time()) - 100  # already expired
        token = _make_jwt(exp)
        result = _jwt_seconds_until_exp(token, default=999)
        assert result == 999

    def test_invalid_token_returns_default(self):
        assert _jwt_seconds_until_exp("not.a.jwt", default=42) == 42

    def test_no_exp_claim_returns_default(self):
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"me"}').rstrip(b"=").decode()
        token = f"{header}.{payload}.sig"
        assert _jwt_seconds_until_exp(token, default=77) == 77

    def test_completely_junk_token_returns_default(self):
        assert _jwt_seconds_until_exp("garbage", default=55) == 55


# ---------------------------------------------------------------------------
# get_breezeway_token behaviour tests
# ---------------------------------------------------------------------------

class TestGetBreezewayToken:
    def _seed_cache(
        self,
        cache_path: pathlib.Path,
        *,
        access_token: str = "acc",
        refresh_token: str = "ref",
        access_expires_at: float,
        refresh_expires_at: float,
        now: float,
    ) -> None:
        fc = FileCache(cache_path)
        with fc.lock():
            fc.write({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "access_expires_at": access_expires_at,
                "refresh_expires_at": refresh_expires_at,
                "fetched_at": now,
            })

    def test_fresh_access_returns_cached_no_http(self, tmp_cache_dir):
        cache_path = tmp_cache_dir / "breezeway.json"
        now = time.time()
        self._seed_cache(
            cache_path,
            access_token="acc_fresh",
            refresh_token="ref_tok",
            access_expires_at=now + 7200,
            refresh_expires_at=now + 86400,
            now=now,
        )
        factory, client = single_factory()
        result = get_breezeway_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        assert result == "acc_fresh"
        assert client.call_count == 0

    def test_expired_access_fresh_refresh_calls_refresh_endpoint(self, tmp_cache_dir):
        cache_path = tmp_cache_dir / "breezeway.json"
        now = time.time()
        self._seed_cache(
            cache_path,
            access_token="acc_expired",
            refresh_token="ref_valid",
            access_expires_at=now + 60,    # within 30-min buffer
            refresh_expires_at=now + 86400,
            now=now,
        )
        body = _ok_body("acc_new", "ref_new")
        factory, client = single_factory(200, body)
        result = get_breezeway_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        assert result == "acc_new"
        assert client.call_count == 1
        assert "refresh" in (client.last_url or ""), (
            f"Expected refresh endpoint, got: {client.last_url}"
        )

    def test_expired_access_expired_refresh_calls_full_auth(self, tmp_cache_dir):
        cache_path = tmp_cache_dir / "breezeway.json"
        now = time.time()
        self._seed_cache(
            cache_path,
            access_token="acc_expired",
            refresh_token="ref_expired",
            access_expires_at=now - 100,
            refresh_expires_at=now - 100,
            now=now - 90000,
        )
        body = _ok_body("acc_full", "ref_full")
        factory, client = single_factory(200, body)
        result = get_breezeway_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        assert result == "acc_full"
        assert client.call_count == 1
        # Should hit the full auth URL, not the refresh URL.
        assert client.last_url is not None
        assert "refresh" not in client.last_url

    def test_no_cache_full_auth(self, tmp_cache_dir):
        cache_path = tmp_cache_dir / "breezeway.json"
        factory, client = single_factory(200, _ok_body("acc_brand_new", "ref_brand_new"))
        result = get_breezeway_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            http_client_factory=factory,
        )
        assert result == "acc_brand_new"
        assert client.call_count == 1

    def test_missing_env_vars_raises(self, tmp_cache_dir, monkeypatch):
        monkeypatch.delenv("BREEZEWAY_CLIENT_ID", raising=False)
        monkeypatch.delenv("BREEZEWAY_CLIENT_SECRET", raising=False)
        with pytest.raises(ConfigurationError, match="BREEZEWAY_CLIENT_ID"):
            get_breezeway_token(cache_path=tmp_cache_dir / "breezeway.json")

    def test_429_on_full_auth_raises_rate_limited(self, tmp_cache_dir):
        factory, _ = single_factory(429, {"detail": "rate limited"})
        with pytest.raises(RateLimitedError):
            get_breezeway_token(
                client_id="cid",
                client_secret="csec",
                cache_path=tmp_cache_dir / "breezeway.json",
                http_client_factory=factory,
            )

    def test_non_200_raises_token_fetch_error(self, tmp_cache_dir):
        factory, _ = single_factory(503, {"error": "service_unavailable"})
        with pytest.raises(TokenFetchError, match="status=503"):
            get_breezeway_token(
                client_id="cid",
                client_secret="csec",
                cache_path=tmp_cache_dir / "breezeway.json",
                http_client_factory=factory,
            )

    def test_refresh_401_falls_back_to_full_auth(self, tmp_cache_dir):
        """When the cached refresh_token is rejected, the broker must NOT
        get stuck in a loop — it must drop back to client-credentials auth
        and recover. This was the prod-outage failure mode 2026-05-06."""
        cache_path = tmp_cache_dir / "breezeway.json"
        now = time.time()
        # Cached refresh appears valid by clock, but Breezeway has revoked it.
        self._seed_cache(
            cache_path,
            access_token="acc_expired",
            refresh_token="ref_revoked",
            access_expires_at=now + 60,         # within 30-min buffer
            refresh_expires_at=now + 86400,     # cached as still good
            now=now,
        )
        responses = [
            FakeResponse(401, {"detail": "refresh revoked"}),  # /refresh → 401
            FakeResponse(200, _ok_body("acc_recovered", "ref_recovered")),  # /auth/v1/ → 200
        ]
        factory, state = sequential_factory(responses)
        result = get_breezeway_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        assert result == "acc_recovered"
        assert state["calls"] == 2, "Should call refresh THEN full_auth"
        assert "refresh" in state["urls"][0]
        assert "refresh" not in state["urls"][1]
        # Cache is written with the recovered token, not the revoked one.
        written = FileCache(cache_path).read()
        assert written["access_token"] == "acc_recovered"
        assert written["refresh_token"] == "ref_recovered"

    def test_refresh_503_also_falls_back(self, tmp_cache_dir):
        """Same fallback for any TokenFetchError on refresh — covers
        transient 5xx + malformed responses, not just 401s."""
        cache_path = tmp_cache_dir / "breezeway.json"
        now = time.time()
        self._seed_cache(
            cache_path,
            access_token="acc_old",
            refresh_token="ref_blocked",
            access_expires_at=now + 60,
            refresh_expires_at=now + 86400,
            now=now,
        )
        responses = [
            FakeResponse(503, {"error": "service unavailable"}),
            FakeResponse(200, _ok_body("acc_after_5xx", "ref_after_5xx")),
        ]
        factory, state = sequential_factory(responses)
        result = get_breezeway_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        assert result == "acc_after_5xx"
        assert state["calls"] == 2

    def test_refresh_then_full_auth_failure_clears_cache(self, tmp_cache_dir):
        """If refresh fails AND full_auth fails, the cache is cleared so
        the next call starts from scratch instead of replaying the bad
        refresh token. Without this, a transient outage during the recovery
        window would re-poison the cache."""
        cache_path = tmp_cache_dir / "breezeway.json"
        now = time.time()
        self._seed_cache(
            cache_path,
            access_token="acc_old",
            refresh_token="ref_revoked",
            access_expires_at=now + 60,
            refresh_expires_at=now + 86400,
            now=now,
        )
        responses = [
            FakeResponse(401, {"detail": "refresh revoked"}),
            FakeResponse(503, {"error": "transient"}),  # full_auth also fails
        ]
        factory, _ = sequential_factory(responses)
        with pytest.raises(TokenFetchError):
            get_breezeway_token(
                client_id="cid",
                client_secret="csec",
                cache_path=cache_path,
                now=now,
                http_client_factory=factory,
            )
        # Cache must have been cleared so the next attempt does NOT
        # replay ref_revoked.
        written = FileCache(cache_path).read()
        assert written["refresh_token"] == ""
        assert written["access_token"] == ""

    def test_cache_written_with_correct_fields(self, tmp_cache_dir):
        """After a successful fetch, cache contains all required fields."""
        cache_path = tmp_cache_dir / "breezeway.json"
        factory, _ = single_factory(200, _ok_body("acc_w", "ref_w"))
        now = time.time()
        get_breezeway_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        written = FileCache(cache_path).read()
        assert written is not None
        for key in ("access_token", "refresh_token", "access_expires_at", "refresh_expires_at", "fetched_at"):
            assert key in written, f"Missing key: {key}"
        assert written["access_token"] == "acc_w"
        assert written["refresh_token"] == "ref_w"
