# Threat Model — scmaine-tokens

This document describes what the package protects against, what it does not
protect against, and how operators should respond to a suspected credential leak.

---

## What this package protects against

**Concurrent token refresh from multiple processes.**
Every read/write cycle is guarded by a POSIX advisory file lock (`fcntl.flock`)
on a per-service `.lock` file. Two tools calling `get_guesty_token()` at the
same moment will serialize: the winner writes the cache; the loser reads it.
Guesty's 5-tokens-per-24h budget is never double-spent.

**Crash mid-write leaving the cache corrupted.**
Writes go through `tempfile.mkstemp` in the same directory, then `os.replace`.
`os.replace` is atomic on POSIX (same filesystem). A crash between the two
steps leaves a `.tmp` file behind, not a half-written cache file. The original
cache (if any) is intact; the next call replaces the orphaned `.tmp`. The
`doctor` CLI flags leftover `.tmp` files explicitly.

**Casual file-system enumeration by other users on the same machine.**
The cache directory is `chmod 0700` on every touch. Other OS users cannot `ls`
the directory to learn which services are being used.

**Casual reading of cache files by other users on the same machine.**
Each cache file is `chmod 0600` immediately after being written. Other OS users
with filesystem access cannot read the cached tokens.

**Token content leaking into exception messages or logs.**
When an upstream auth endpoint returns a non-200 response, the package logs the
HTTP status code and the byte-length of the body — never the body itself. When a
required field is missing from a successful response, only the sorted key names
are surfaced, not the values. JSON parse errors are caught explicitly; the
exception message does not include the raw response text.

**Burning the Guesty 5/day budget across multiple tools.**
Without a shared broker, three tools each refreshing their own token would
exhaust the daily allowance in a single morning. The broker's shared cache
means the budget is consumed at most once per 24-hour window regardless of how
many tools are running.

---

## What this package does NOT protect against

**A process running as the same user reading the cache files.**
On a single-user laptop, every tool you run as yourself shares the same trust
boundary by definition — `chmod 0600` provides no protection there. If you need
stronger isolation between tools on the same machine, run sensitive tools in a
separate OS user account.

**Disk-image theft.**
Cache files are not encrypted at rest. macOS users should rely on FileVault;
Linux users on LUKS or an equivalent full-disk encryption scheme. The package
cannot protect plaintext files from offline access to the raw disk.

**Backup and sync exfiltration.**
macOS Time Machine excludes `~/.cache/` by default. Verify your backup tool
applies the same exclusion. Do not point Dropbox, iCloud Drive, or similar
sync clients at `~/.cache/scmaine-tokens/` — they would silently upload cached
tokens to cloud storage.

**Network-level interception of the OAuth refresh request.**
The package relies on HTTPS to the upstream provider (Guesty, Breezeway). TLS
certificate validation is performed by httpx (the default behavior). Mitigation
of a compromised CA or TLS MITM is out of scope for a token broker.

**Compromise of the upstream OAuth provider.**
If Guesty or Breezeway leaks your `client_id`/`client_secret`, the broker
cannot help. Rotate secrets upstream immediately; see the incident response
section below.

**Malicious code in dependencies.**
httpx and its transitive dependencies are pinned to exact versions in
`pyproject.toml`, reducing the window for a compromised package to slip in
unnoticed. The supply-chain rules in `~/.claude/CLAUDE.md` govern this for
downstream consumers.

---

## Operational guidance

**Routine auditing.**
Run `python -m scmaine_tokens.doctor` (or `scmaine-tokens-doctor` after install)
on any machine that uses the broker. It checks directory and file permissions,
reports token expiry without printing values, flags stale lock files and
orphaned temp files, and lists missing environment variables. Exit code 0 means
clean; exit code 1 means at least one issue needs attention.

**Secret rotation schedule.**
Rotate `client_secret` values in the Guesty and Breezeway provider dashboards
at least annually. After rotation: update `~/.env` and any GitHub Actions
secrets that hold the old value. The broker will automatically re-authenticate
on the next call once the new credentials are in the environment.

**Incident response — suspected leak.**
1. Revoke the affected `client_secret` in the upstream provider dashboard
   (Guesty or Breezeway). This invalidates all cached tokens immediately.
2. Delete the affected cache file:
   `rm ~/.cache/scmaine-tokens/guesty.json` or `breezeway.json`.
3. Update the secret in `~/.env` and any CI/CD secrets stores (GitHub Actions,
   Railway environment).
4. Verify `python -m scmaine_tokens.doctor` reports no stale files and the
   new secret is present.
5. The next `get_guesty_token()` / `get_breezeway_token()` call will
   re-authenticate with the new credentials.

**Railway containers.**
Containers are ephemeral — the default cache path (`~/.cache/scmaine-tokens/`)
does not survive a restart. Mount a Railway Volume at a stable path and set
`SCMAINE_TOKENS_CACHE_DIR` to that path. Without this, every container restart
burns one of Guesty's 5 daily tokens and may trigger Breezeway's rate limit.

---

## Future enhancements considered and deferred

**macOS Keychain backend.**
Would protect cached tokens from same-user processes (e.g., a compromised
script running as the same user). Deferred because the current threat model —
single-user laptop, all tools written and run by the same person — does not
justify the additional complexity (subprocess prompts, cross-platform fallback,
keychain permission dialogs in CI). Revisit if the workspace grows to a
multi-user or multi-service-account model.

**Token rotation hooks.**
Emit a webhook or structured log event each time a token is refreshed, so an
observability platform can track refresh frequency and flag anomalies. Deferred
until there is a concrete monitoring requirement (e.g., a dashboard watching
for unexpected refresh spikes that might indicate a cache miss or a process
ignoring the broker).
