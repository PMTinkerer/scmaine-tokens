"""Unit tests for guesty.py."""

import pathlib
import threading
import time
from typing import Optional
from unittest.mock import MagicMock

import pytest

from scmaine_tokens.errors import ConfigurationError, RateLimitedError, TokenFetchError
from scmaine_tokens.guesty import _REFRESH_BUFFER_S, get_guesty_token


# ---------------------------------------------------------------------------
# Fake httpx plumbing
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code: int, body: dict) -> None:
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self) -> dict:
        return self._body


class FakeClient:
    """Context-manager-compatible fake httpx.Client."""

    def __init__(self, response: FakeResponse) -> None:
        self._response = response
        self.call_count = 0
        self.last_kwargs = {}

    def post(self, url: str, **kwargs):
        self.call_count += 1
        self.last_kwargs = kwargs
        return self._response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def make_factory(status_code: int, body: dict):
    """Return a factory callable and the FakeClient it will produce."""
    client = FakeClient(FakeResponse(status_code, body))
    return (lambda: client), client


def ok_factory(access_token: str = "tok_abc", expires_in: int = 86400):
    return make_factory(200, {"access_token": access_token, "expires_in": expires_in})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCachedToken:
    def test_fresh_cache_skips_http(self, tmp_cache_dir):
        """If the cache has a non-expired token, no HTTP call is made."""
        cache_path = tmp_cache_dir / "guesty.json"
        factory, client = ok_factory("tok_fresh")

        # Seed the cache with a token that won't expire for 2 hours.
        now = time.time()
        from scmaine_tokens._cache import FileCache
        fc = FileCache(cache_path)
        with fc.lock():
            fc.write({
                "access_token": "tok_fresh",
                "expires_at": now + 7200,
                "fetched_at": now,
                "client_id": "cid",
            })

        result = get_guesty_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        assert result == "tok_fresh"
        assert client.call_count == 0

    def test_no_cache_fetches_and_writes(self, tmp_cache_dir):
        """With no cache, token is fetched and the cache file is written."""
        cache_path = tmp_cache_dir / "guesty.json"
        factory, client = ok_factory("tok_new", expires_in=3600)
        now = time.time()

        result = get_guesty_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        assert result == "tok_new"
        assert client.call_count == 1

        from scmaine_tokens._cache import FileCache
        written = FileCache(cache_path).read()
        assert written is not None
        assert written["access_token"] == "tok_new"
        assert abs(written["expires_at"] - (now + 3600)) < 1

    def test_token_within_refresh_buffer_refetches(self, tmp_cache_dir):
        """Token expiring within the 30-min buffer triggers a refresh."""
        cache_path = tmp_cache_dir / "guesty.json"
        now = time.time()

        from scmaine_tokens._cache import FileCache
        fc = FileCache(cache_path)
        with fc.lock():
            fc.write({
                "access_token": "tok_stale",
                # expires in 10 minutes — within the 30-min buffer
                "expires_at": now + 600,
                "fetched_at": now - 3600,
                "client_id": "cid",
            })

        factory, client = ok_factory("tok_refreshed")
        result = get_guesty_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        assert result == "tok_refreshed"
        assert client.call_count == 1

    def test_expired_token_refetches(self, tmp_cache_dir):
        """Fully expired token triggers a fetch."""
        cache_path = tmp_cache_dir / "guesty.json"
        now = time.time()

        from scmaine_tokens._cache import FileCache
        fc = FileCache(cache_path)
        with fc.lock():
            fc.write({
                "access_token": "tok_expired",
                "expires_at": now - 100,  # already expired
                "fetched_at": now - 90000,
                "client_id": "cid",
            })

        factory, client = ok_factory("tok_new_after_expiry")
        result = get_guesty_token(
            client_id="cid",
            client_secret="csec",
            cache_path=cache_path,
            now=now,
            http_client_factory=factory,
        )
        assert result == "tok_new_after_expiry"
        assert client.call_count == 1


class TestErrors:
    def test_missing_env_vars_raises_configuration_error(self, tmp_cache_dir, monkeypatch):
        monkeypatch.delenv("GUESTY_CLIENT_ID", raising=False)
        monkeypatch.delenv("GUESTY_CLIENT_SECRET", raising=False)
        with pytest.raises(ConfigurationError, match="GUESTY_CLIENT_ID"):
            get_guesty_token(cache_path=tmp_cache_dir / "guesty.json")

    def test_429_raises_rate_limited_error(self, tmp_cache_dir):
        factory, _ = make_factory(429, {"error": "rate_limited"})
        with pytest.raises(RateLimitedError):
            get_guesty_token(
                client_id="cid",
                client_secret="csec",
                cache_path=tmp_cache_dir / "guesty.json",
                http_client_factory=factory,
            )

    def test_non_200_raises_token_fetch_error(self, tmp_cache_dir):
        factory, _ = make_factory(500, {"error": "server_error"})
        with pytest.raises(TokenFetchError, match="status=500"):
            get_guesty_token(
                client_id="cid",
                client_secret="csec",
                cache_path=tmp_cache_dir / "guesty.json",
                http_client_factory=factory,
            )

    def test_missing_access_token_in_response_raises(self, tmp_cache_dir):
        factory, _ = make_factory(200, {"token_type": "Bearer"})
        with pytest.raises(TokenFetchError, match="missing access_token"):
            get_guesty_token(
                client_id="cid",
                client_secret="csec",
                cache_path=tmp_cache_dir / "guesty.json",
                http_client_factory=factory,
            )


class TestConcurrency:
    def test_two_concurrent_calls_fetch_once(self, tmp_cache_dir):
        """Two threads calling get_guesty_token concurrently should only trigger
        one HTTP fetch thanks to the file lock."""
        cache_path = tmp_cache_dir / "guesty.json"
        call_counts = []
        errors = []
        barrier = threading.Barrier(2)

        # Use a shared fake client to count calls across threads.
        shared_client = FakeClient(FakeResponse(200, {"access_token": "tok_shared", "expires_in": 86400}))

        def factory():
            return shared_client

        def fetch():
            try:
                barrier.wait()  # both threads start at the same time
                get_guesty_token(
                    client_id="cid",
                    client_secret="csec",
                    cache_path=cache_path,
                    http_client_factory=factory,
                )
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=fetch)
        t2 = threading.Thread(target=fetch)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert errors == [], f"Thread errors: {errors}"
        # The lock serializes access: only one thread fetches a new token;
        # the second sees the already-written cache. HTTP calls == 1.
        assert shared_client.call_count == 1, (
            f"Expected 1 HTTP call, got {shared_client.call_count}"
        )
