"""Audit CLI for the scmaine-tokens cache.

Usage: python -m scmaine_tokens.doctor
       (or: scmaine-tokens-doctor after pip install)

Checks the cache directory permissions, each service's cached token file,
stale lock files, temp-file leftovers, and required environment variables.

Exit code 0 if no issues, 1 if any warnings or errors.
Token values are NEVER printed — only <redacted, len=N> placeholders.
"""

import argparse
import json
import os
import pathlib
import stat
import sys
import time
from typing import Callable, List

from scmaine_tokens._cache import _resolve_cache_dir


GUESTY_FILE = "guesty.json"
BREEZEWAY_FILE = "breezeway.json"

REQUIRED_ENV_VARS = (
    "GUESTY_CLIENT_ID",
    "GUESTY_CLIENT_SECRET",
    "BREEZEWAY_CLIENT_ID",
    "BREEZEWAY_CLIENT_SECRET",
    "NOTION_TOKEN",
)


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit the scmaine-tokens cache and configuration."
    )
    parser.parse_args(argv)

    cache_dir = _resolve_cache_dir()
    issues: List[str] = []

    print("scmaine-tokens doctor")
    print("=" * 50)
    print(f"Cache directory: {cache_dir}")
    print(
        f"  override env (SCMAINE_TOKENS_CACHE_DIR): "
        f"{os.environ.get('SCMAINE_TOKENS_CACHE_DIR') or '(not set)'}"
    )

    issues.extend(_check_cache_dir_mode(cache_dir))
    issues.extend(_check_service_file(cache_dir, GUESTY_FILE, _summarize_guesty))
    issues.extend(_check_service_file(cache_dir, BREEZEWAY_FILE, _summarize_breezeway))
    issues.extend(_check_for_stale_locks(cache_dir))
    issues.extend(_check_for_tmp_leftovers(cache_dir))
    issues.extend(_check_env_vars())

    print()
    if issues:
        print(f"  {len(issues)} issue(s) found:")
        for issue in issues:
            print(f"  - {issue}")
        return 1
    print("No issues found.")
    return 0


def _check_cache_dir_mode(path: pathlib.Path) -> List[str]:
    issues = []
    if not path.exists():
        print("  (does not exist yet)")
        issues.append("Cache directory does not exist")
        return issues
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        print(f"  permissions: {oct(mode)}", end="")
        if mode == 0o700:
            print("  [OK]")
        else:
            print("  [WARN: expected 0o700]")
            issues.append(f"Cache dir mode is {oct(mode)}, expected 0o700")
    except OSError as exc:
        issues.append(f"Cannot stat cache dir: {exc}")
    return issues


def _check_service_file(
    cache_dir: pathlib.Path,
    filename: str,
    summarizer: Callable[[dict], List[str]],
) -> List[str]:
    path = cache_dir / filename
    print()
    print(f"{filename}:")
    if not path.exists():
        print("  (no cache yet -- first call will populate it)")
        return []

    issues = []
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        print(f"  permissions: {oct(mode)}", end="")
        if mode == 0o600:
            print("  [OK]")
        else:
            print("  [WARN: expected 0o600]")
            issues.append(f"{filename}: mode is {oct(mode)}, expected 0o600")
    except OSError as exc:
        return [f"{filename}: cannot stat ({exc})"]

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        issues.append(f"{filename}: cannot read ({exc.__class__.__name__})")
        return issues
    except json.JSONDecodeError as exc:
        issues.append(f"{filename}: not valid JSON ({exc.__class__.__name__})")
        return issues

    if not isinstance(data, dict):
        issues.append(f"{filename}: not a JSON object")
        return issues

    issues.extend(summarizer(data))
    return issues


def _summarize_guesty(data: dict) -> List[str]:
    issues = []
    token = data.get("access_token", "")
    print(f"  access_token: <redacted, len={len(token)}>")
    expires_at = data.get("expires_at", 0)
    issues.extend(_summarize_expiry("access_token", expires_at))
    return issues


def _summarize_breezeway(data: dict) -> List[str]:
    issues = []
    access = data.get("access_token", "")
    refresh = data.get("refresh_token", "")
    print(f"  access_token: <redacted, len={len(access)}>")
    print(f"  refresh_token: <redacted, len={len(refresh)}>")
    issues.extend(_summarize_expiry("access_token", data.get("access_expires_at", 0)))
    issues.extend(_summarize_expiry("refresh_token", data.get("refresh_expires_at", 0)))
    return issues


def _summarize_expiry(label: str, expires_at: float) -> List[str]:
    issues = []
    now = time.time()
    delta = expires_at - now
    pretty = _humanize_duration(abs(delta))
    if delta > 0:
        print(f"  {label} expires in: {pretty}")
    else:
        print(f"  {label}: EXPIRED {pretty} ago")
        issues.append(f"{label} is expired (will refresh on next request)")
    return issues


def _humanize_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{int(minutes)}m"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f}h"
    days = hours / 24
    return f"{days:.1f}d"


def _check_for_stale_locks(cache_dir: pathlib.Path) -> List[str]:
    issues = []
    now = time.time()
    for lock in cache_dir.glob("*.lock"):
        try:
            age = now - lock.stat().st_mtime
        except OSError:
            continue
        if age > 3600:
            issues.append(
                f"Stale lock file: {lock.name} (age {_humanize_duration(age)}). "
                f"A crashed refresh may have left this; safe to delete."
            )
    return issues


def _check_for_tmp_leftovers(cache_dir: pathlib.Path) -> List[str]:
    issues = []
    leftover = list(cache_dir.glob("*.tmp")) + list(cache_dir.glob("*.tmp.*"))
    for f in leftover:
        issues.append(
            f"Tmp file leftover: {f.name}. Indicates a crashed write; safe to delete."
        )
    return issues


def _check_env_vars() -> List[str]:
    print()
    print("Environment variables:")
    issues = []
    for var in REQUIRED_ENV_VARS:
        if os.environ.get(var):
            print(f"  {var}: set")
        else:
            print(f"  {var}: MISSING")
            issues.append(f"Required env var {var} is not set")
    return issues


if __name__ == "__main__":
    sys.exit(main())
