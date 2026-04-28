"""Regression tests pinning leak-prevention behavior in guesty.py and breezeway.py.

These tests exist so that future refactors cannot silently reintroduce the
response-body leak that was fixed in the security hardening pass. They import
internal helpers (_fetch_token, _full_auth, _refresh_auth, _parse_auth_response)
deliberately — the point is to pin exactly what those functions raise.
"""

import pytest

from scmaine_tokens.errors import TokenFetchError, RateLimitedError
from scmaine_tokens.guesty import _fetch_token
from scmaine_tokens.breezeway import _full_auth, _refresh_auth, _parse_auth_response


# ---------------------------------------------------------------------------
# Shared fake HTTP plumbing (independent copy — tests must not share state)
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code, body, text_override=None):
        self.status_code = status_code
        self._body = body
        self.text = text_override if text_override is not None else str(body)

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def make_factory(status_code, body, text_override=None):
    class FakeClient:
        def __init__(self):
            self._resp = FakeResponse(status_code, body, text_override)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None, data=None):
            return self._resp

    return lambda: FakeClient()


# ---------------------------------------------------------------------------
# Guesty redaction tests
# ---------------------------------------------------------------------------

class TestGuestyRedaction:
    def test_non_200_error_does_not_include_response_body(self):
        secret = "leaked_token_value_DO_NOT_LOG"
        factory = make_factory(500, {}, text_override=secret)
        with pytest.raises(TokenFetchError) as exc:
            _fetch_token("cid", "csec", http_client_factory=factory)
        assert secret not in str(exc.value)
        assert "redacted" in str(exc.value).lower()
        assert "status=500" in str(exc.value)

    def test_invalid_json_response_does_not_include_body(self):
        secret = "leaked_token_value_DO_NOT_LOG"
        # body=ValueError causes resp.json() to raise; text=secret simulates
        # an unparseable response that contains sensitive content.
        factory = make_factory(200, ValueError("not json"), text_override=secret)
        with pytest.raises(TokenFetchError) as exc:
            _fetch_token("cid", "csec", http_client_factory=factory)
        assert secret not in str(exc.value)
        assert "redacted" in str(exc.value).lower()

    def test_missing_access_token_error_lists_keys_not_values(self):
        secret_value = "this_should_never_appear_in_error"
        factory = make_factory(200, {"refresh_token": secret_value, "expires_in": 3600})
        with pytest.raises(TokenFetchError) as exc:
            _fetch_token("cid", "csec", http_client_factory=factory)
        assert secret_value not in str(exc.value)
        # Key NAMES are fine; values are not.
        assert "refresh_token" in str(exc.value)
        assert "expires_in" in str(exc.value)
        assert "redacted" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Breezeway redaction tests
# ---------------------------------------------------------------------------

class TestBreezewayRedaction:
    def test_non_200_error_does_not_include_response_body(self):
        secret = "breezeway_secret_DO_NOT_LOG"
        factory = make_factory(500, {}, text_override=secret)
        with pytest.raises(TokenFetchError) as exc:
            _full_auth("cid", "csec", http_client_factory=factory)
        assert secret not in str(exc.value)
        assert "redacted" in str(exc.value).lower()
        assert "status=500" in str(exc.value)

    def test_missing_token_error_lists_keys_not_values(self):
        secret_value = "this_should_never_appear_in_error"
        factory = make_factory(200, {"some_other_field": secret_value})
        with pytest.raises(TokenFetchError) as exc:
            _full_auth("cid", "csec", http_client_factory=factory)
        assert secret_value not in str(exc.value)
        assert "some_other_field" in str(exc.value)
        assert "redacted" in str(exc.value).lower()

    def test_refresh_path_also_redacts(self):
        secret = "refresh_path_secret_DO_NOT_LOG"
        factory = make_factory(401, {}, text_override=secret)
        with pytest.raises(TokenFetchError) as exc:
            _refresh_auth("ref_tok", http_client_factory=factory)
        assert secret not in str(exc.value)

    def test_non_200_error_includes_status_code(self):
        factory = make_factory(403, {}, text_override="some body")
        with pytest.raises(TokenFetchError) as exc:
            _full_auth("cid", "csec", http_client_factory=factory)
        assert "status=403" in str(exc.value)

    def test_invalid_json_breezeway_does_not_include_body(self):
        secret = "breezeway_json_error_DO_NOT_LOG"
        factory = make_factory(200, ValueError("bad json"), text_override=secret)
        with pytest.raises(TokenFetchError) as exc:
            _full_auth("cid", "csec", http_client_factory=factory)
        assert secret not in str(exc.value)
        assert "redacted" in str(exc.value).lower()

    def test_parse_auth_response_redacts_on_non_200(self):
        """_parse_auth_response is the shared path for both _full_auth and _refresh_auth."""
        secret = "shared_parse_secret_DO_NOT_LOG"

        class FakeResp:
            status_code = 500
            text = secret

            def json(self):
                return {}

        with pytest.raises(TokenFetchError) as exc:
            _parse_auth_response(FakeResp())
        assert secret not in str(exc.value)
        assert "redacted" in str(exc.value).lower()
