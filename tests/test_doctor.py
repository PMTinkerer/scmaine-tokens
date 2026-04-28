"""Tests for the scmaine-tokens audit CLI (doctor.py)."""

import json
import os
import pathlib
import stat
import time

import pytest

from scmaine_tokens.doctor import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_guesty(cache_dir: pathlib.Path, access_token: str, expires_at: float) -> pathlib.Path:
    path = cache_dir / "guesty.json"
    path.write_text(
        json.dumps({
            "access_token": access_token,
            "expires_at": expires_at,
            "fetched_at": time.time(),
            "client_id": "test_cid",
        }),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path


def _write_breezeway(
    cache_dir: pathlib.Path,
    access_token: str,
    refresh_token: str,
    access_expires_at: float,
    refresh_expires_at: float,
) -> pathlib.Path:
    path = cache_dir / "breezeway.json"
    path.write_text(
        json.dumps({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_expires_at": access_expires_at,
            "refresh_expires_at": refresh_expires_at,
            "fetched_at": time.time(),
        }),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDoctorEmptyCache:
    def test_empty_cache_dir_exits_with_issues(self, tmp_cache_dir, capsys, monkeypatch):
        """An empty cache dir has no service files (that's fine) but all env
        vars are missing — expect exit 1 with 'no cache yet' for each service."""
        for var in ("GUESTY_CLIENT_ID", "GUESTY_CLIENT_SECRET",
                    "BREEZEWAY_CLIENT_ID", "BREEZEWAY_CLIENT_SECRET", "NOTION_TOKEN"):
            monkeypatch.delenv(var, raising=False)

        code = main([])
        out = capsys.readouterr().out

        assert code == 1
        assert "no cache yet" in out.lower()
        assert "MISSING" in out

    def test_empty_cache_dir_no_service_files_mentioned_but_present(
        self, tmp_cache_dir, capsys, monkeypatch
    ):
        """Confirm 'no cache yet' appears for both guesty.json and breezeway.json."""
        for var in ("GUESTY_CLIENT_ID", "GUESTY_CLIENT_SECRET",
                    "BREEZEWAY_CLIENT_ID", "BREEZEWAY_CLIENT_SECRET", "NOTION_TOKEN"):
            monkeypatch.delenv(var, raising=False)

        main([])
        out = capsys.readouterr().out
        # Both service file sections should say no cache yet.
        assert out.count("no cache yet") == 2


class TestDoctorCacheDirPermissions:
    def test_cache_dir_mode_755_reports_issue(self, tmp_cache_dir, capsys, monkeypatch):
        """Wrong directory permissions → exit 1 with expected 0o700 in output."""
        for var in ("GUESTY_CLIENT_ID", "GUESTY_CLIENT_SECRET",
                    "BREEZEWAY_CLIENT_ID", "BREEZEWAY_CLIENT_SECRET", "NOTION_TOKEN"):
            monkeypatch.delenv(var, raising=False)

        os.chmod(tmp_cache_dir, 0o755)
        code = main([])
        out = capsys.readouterr().out

        assert code == 1
        assert "0o700" in out

        # Reset so tmp_path cleanup doesn't fail.
        os.chmod(tmp_cache_dir, 0o700)


class TestDoctorGuestyExpiry:
    def test_expired_token_exits_1_and_shows_expired(self, tmp_cache_dir, capsys, monkeypatch):
        """A guesty.json with an expired token → exit 1, 'EXPIRED' in output."""
        for var in ("GUESTY_CLIENT_ID", "GUESTY_CLIENT_SECRET",
                    "BREEZEWAY_CLIENT_ID", "BREEZEWAY_CLIENT_SECRET", "NOTION_TOKEN"):
            monkeypatch.delenv(var, raising=False)

        _write_guesty(tmp_cache_dir, "tok_expired_value", time.time() - 3600)
        code = main([])
        out = capsys.readouterr().out

        assert code == 1
        assert "EXPIRED" in out

    def test_expired_token_does_not_print_token_value(self, tmp_cache_dir, capsys, monkeypatch):
        """Even when a token is expired, the value must not appear in output."""
        for var in ("GUESTY_CLIENT_ID", "GUESTY_CLIENT_SECRET",
                    "BREEZEWAY_CLIENT_ID", "BREEZEWAY_CLIENT_SECRET", "NOTION_TOKEN"):
            monkeypatch.delenv(var, raising=False)

        secret = "tok_expired_value"
        _write_guesty(tmp_cache_dir, secret, time.time() - 3600)
        main([])
        out = capsys.readouterr().out

        assert secret not in out

    def test_fresh_token_exits_0_for_expiry_check(self, tmp_cache_dir, capsys, monkeypatch):
        """Fresh guesty token → no expiry issue; 'expires in' in output."""
        # Provide all env vars so missing-var issues don't interfere.
        monkeypatch.setenv("GUESTY_CLIENT_ID", "cid")
        monkeypatch.setenv("GUESTY_CLIENT_SECRET", "csec")
        monkeypatch.setenv("BREEZEWAY_CLIENT_ID", "bcid")
        monkeypatch.setenv("BREEZEWAY_CLIENT_SECRET", "bcsec")
        monkeypatch.setenv("NOTION_TOKEN", "ntoken")

        _write_guesty(tmp_cache_dir, "tok_fresh_value", time.time() + 12 * 3600)
        code = main([])
        out = capsys.readouterr().out

        assert code == 0
        assert "expires in" in out.lower()

    def test_fresh_token_does_not_print_token_value(self, tmp_cache_dir, capsys, monkeypatch):
        """Fresh token output must not include the token value."""
        monkeypatch.setenv("GUESTY_CLIENT_ID", "cid")
        monkeypatch.setenv("GUESTY_CLIENT_SECRET", "csec")
        monkeypatch.setenv("BREEZEWAY_CLIENT_ID", "bcid")
        monkeypatch.setenv("BREEZEWAY_CLIENT_SECRET", "bcsec")
        monkeypatch.setenv("NOTION_TOKEN", "ntoken")

        secret = "tok_fresh_secret_value"
        _write_guesty(tmp_cache_dir, secret, time.time() + 12 * 3600)
        main([])
        out = capsys.readouterr().out

        assert secret not in out
        assert "redacted" in out.lower()


class TestDoctorTmpFiles:
    def test_tmp_file_in_cache_exits_1(self, tmp_cache_dir, capsys, monkeypatch):
        """A .tmp file in the cache dir → exit 1, 'Tmp file leftover' in output."""
        for var in ("GUESTY_CLIENT_ID", "GUESTY_CLIENT_SECRET",
                    "BREEZEWAY_CLIENT_ID", "BREEZEWAY_CLIENT_SECRET", "NOTION_TOKEN"):
            monkeypatch.delenv(var, raising=False)

        (tmp_cache_dir / "guesty.json.tmp").write_text("{}", encoding="utf-8")
        code = main([])
        out = capsys.readouterr().out

        assert code == 1
        assert "Tmp file leftover" in out

    def test_tmp_dot_suffix_also_caught(self, tmp_cache_dir, capsys, monkeypatch):
        """A .tmp.XXXX file (mkstemp pattern) is also flagged."""
        for var in ("GUESTY_CLIENT_ID", "GUESTY_CLIENT_SECRET",
                    "BREEZEWAY_CLIENT_ID", "BREEZEWAY_CLIENT_SECRET", "NOTION_TOKEN"):
            monkeypatch.delenv(var, raising=False)

        (tmp_cache_dir / "guesty.json.tmp.abc123").write_text("{}", encoding="utf-8")
        code = main([])
        out = capsys.readouterr().out

        assert code == 1
        assert "Tmp file leftover" in out


class TestDoctorEnvVars:
    def test_missing_env_var_exits_1(self, tmp_cache_dir, capsys, monkeypatch):
        """Any missing required env var → exit 1, 'MISSING' in output."""
        for var in ("GUESTY_CLIENT_ID", "GUESTY_CLIENT_SECRET",
                    "BREEZEWAY_CLIENT_ID", "BREEZEWAY_CLIENT_SECRET", "NOTION_TOKEN"):
            monkeypatch.delenv(var, raising=False)

        code = main([])
        out = capsys.readouterr().out

        assert code == 1
        assert "MISSING" in out

    def test_all_env_vars_set_no_env_issues(self, tmp_cache_dir, capsys, monkeypatch):
        """All env vars set → no env var issues in output."""
        monkeypatch.setenv("GUESTY_CLIENT_ID", "cid")
        monkeypatch.setenv("GUESTY_CLIENT_SECRET", "csec")
        monkeypatch.setenv("BREEZEWAY_CLIENT_ID", "bcid")
        monkeypatch.setenv("BREEZEWAY_CLIENT_SECRET", "bcsec")
        monkeypatch.setenv("NOTION_TOKEN", "ntoken")

        main([])
        out = capsys.readouterr().out

        assert "MISSING" not in out
        # Each var should show as 'set'
        for var in ("GUESTY_CLIENT_ID", "GUESTY_CLIENT_SECRET",
                    "BREEZEWAY_CLIENT_ID", "BREEZEWAY_CLIENT_SECRET", "NOTION_TOKEN"):
            assert f"{var}: set" in out


class TestDoctorTokenLeakPrevention:
    """Crucial regression: the audit CLI must never print token values."""

    def test_guesty_token_never_printed(self, tmp_cache_dir, capsys, monkeypatch):
        monkeypatch.setenv("GUESTY_CLIENT_ID", "cid")
        monkeypatch.setenv("GUESTY_CLIENT_SECRET", "csec")
        monkeypatch.setenv("BREEZEWAY_CLIENT_ID", "bcid")
        monkeypatch.setenv("BREEZEWAY_CLIENT_SECRET", "bcsec")
        monkeypatch.setenv("NOTION_TOKEN", "ntoken")

        secret = "secret_token_value_DO_NOT_LEAK"
        _write_guesty(tmp_cache_dir, secret, time.time() + 86400)
        main([])
        out = capsys.readouterr().out

        assert secret not in out
        assert "redacted" in out.lower()

    def test_breezeway_tokens_never_printed(self, tmp_cache_dir, capsys, monkeypatch):
        monkeypatch.setenv("GUESTY_CLIENT_ID", "cid")
        monkeypatch.setenv("GUESTY_CLIENT_SECRET", "csec")
        monkeypatch.setenv("BREEZEWAY_CLIENT_ID", "bcid")
        monkeypatch.setenv("BREEZEWAY_CLIENT_SECRET", "bcsec")
        monkeypatch.setenv("NOTION_TOKEN", "ntoken")

        access_secret = "breezeway_access_secret_DO_NOT_LEAK"
        refresh_secret = "breezeway_refresh_secret_DO_NOT_LEAK"
        _write_breezeway(
            tmp_cache_dir,
            access_secret,
            refresh_secret,
            time.time() + 3600,
            time.time() + 86400 * 30,
        )
        main([])
        out = capsys.readouterr().out

        assert access_secret not in out
        assert refresh_secret not in out

    def test_redacted_placeholder_shown_for_guesty(self, tmp_cache_dir, capsys, monkeypatch):
        """Output should show '<redacted, len=N>' not the raw token."""
        monkeypatch.setenv("GUESTY_CLIENT_ID", "cid")
        monkeypatch.setenv("GUESTY_CLIENT_SECRET", "csec")
        monkeypatch.setenv("BREEZEWAY_CLIENT_ID", "bcid")
        monkeypatch.setenv("BREEZEWAY_CLIENT_SECRET", "bcsec")
        monkeypatch.setenv("NOTION_TOKEN", "ntoken")

        secret = "tok_len_check_value"  # len=18
        _write_guesty(tmp_cache_dir, secret, time.time() + 86400)
        main([])
        out = capsys.readouterr().out

        assert f"<redacted, len={len(secret)}>" in out

    def test_redacted_placeholder_shown_for_breezeway(self, tmp_cache_dir, capsys, monkeypatch):
        """Both breezeway token fields show redacted placeholders."""
        monkeypatch.setenv("GUESTY_CLIENT_ID", "cid")
        monkeypatch.setenv("GUESTY_CLIENT_SECRET", "csec")
        monkeypatch.setenv("BREEZEWAY_CLIENT_ID", "bcid")
        monkeypatch.setenv("BREEZEWAY_CLIENT_SECRET", "bcsec")
        monkeypatch.setenv("NOTION_TOKEN", "ntoken")

        access_secret = "bw_access_tok_val"   # len=17
        refresh_secret = "bw_refresh_tok_val"  # len=18
        _write_breezeway(
            tmp_cache_dir,
            access_secret,
            refresh_secret,
            time.time() + 3600,
            time.time() + 86400 * 30,
        )
        main([])
        out = capsys.readouterr().out

        assert f"<redacted, len={len(access_secret)}>" in out
        assert f"<redacted, len={len(refresh_secret)}>" in out
