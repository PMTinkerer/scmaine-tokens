# scmaine-tokens

Shared OAuth token broker for the SCMaine workspace. Centralises token
management for Guesty, Breezeway, and Notion so that multiple tools share one
cached credential instead of each refreshing independently.

## Why this exists

| Service | Constraint | Blast radius without a broker |
|---------|-----------|-------------------------------|
| Guesty | 5 OAuth token requests per 24 hours per `client_id` | 3 tools refreshing independently = 3× the burn rate |
| Breezeway | ~1 auth request per minute | Parallel CI runs can immediately hit 429 |
| Notion | Static integration token (no rotation) | Low risk, but uniform interface is worth it |

## Install

From any consuming project's virtual environment:

```bash
pip install -e /Users/lucasknowles/scmaine-tokens
```

Or pin it in `requirements.txt` (for editable installs in CI, use the path form):

```
-e /Users/lucasknowles/scmaine-tokens
```

## Usage

```python
from scmaine_tokens import get_guesty_token, get_breezeway_token, get_notion_token

# Guesty — reads GUESTY_CLIENT_ID + GUESTY_CLIENT_SECRET from env.
# Returns a cached token; fetches a new one only when within 30 min of expiry.
token = get_guesty_token()

# Breezeway — reads BREEZEWAY_CLIENT_ID + BREEZEWAY_CLIENT_SECRET from env.
# Uses refresh_token rotation; full re-auth only when refresh token expires.
token = get_breezeway_token()

# Notion — reads NOTION_TOKEN from env. No caching (static token).
token = get_notion_token()
```

All three functions raise `ConfigurationError` if required env vars are
missing, and `TokenFetchError` / `RateLimitedError` on upstream failures.

## Required env vars

| Function | Env var(s) |
|----------|------------|
| `get_guesty_token()` | `GUESTY_CLIENT_ID`, `GUESTY_CLIENT_SECRET` |
| `get_breezeway_token()` | `BREEZEWAY_CLIENT_ID`, `BREEZEWAY_CLIENT_SECRET` |
| `get_notion_token()` | `NOTION_TOKEN` |

## Cache location

Tokens are cached in JSON files under:

```
~/.cache/scmaine-tokens/
├── guesty.json        # chmod 600
├── guesty.json.lock   # advisory lock file
├── breezeway.json     # chmod 600
└── breezeway.json.lock
```

Override the directory by setting `SCMAINE_TOKENS_CACHE_DIR` (useful for
Railway containers with a mounted volume, or for isolated test runs):

```bash
export SCMAINE_TOKENS_CACHE_DIR=/mnt/token-cache
```

## Concurrency safety

Every token read/write is protected by a POSIX advisory file lock
(`fcntl.flock`) on a separate `.lock` file. Cache writes are atomic:

1. JSON is written to a temp file in the same directory (same filesystem).
2. `os.replace()` atomically swaps it onto the final path.
3. The file is `chmod 0600` immediately after.

This means two processes calling `get_guesty_token()` simultaneously will
only ever issue one HTTP request — the second caller waits for the lock, then
reads the token the first caller already wrote.

## Warning: live API calls in CI burn Guesty budget

Running tests against the live Guesty API in CI will consume one of your 5
daily tokens per workflow run. Recommended mitigation: cache the
`~/.cache/scmaine-tokens/` directory in GitHub Actions, keyed by ISO date, so
multiple workflows on the same day share one token:

```yaml
- uses: actions/cache@<sha>  # pin to full SHA
  with:
    path: ~/.cache/scmaine-tokens
    key: scmaine-tokens-${{ env.TODAY }}
  env:
    TODAY: ${{ steps.date.outputs.date }}
```

The broker itself handles expiry correctly — cached tokens are always validated
before use, so a stale cache entry from a previous day will trigger a refresh.

## Security

This package treats tokens as critical infrastructure: cache files are `chmod 0600`,
the cache directory is `chmod 0700`, every refresh is atomic and locked against
concurrent writers, and exception messages NEVER include response bodies (which
could echo tokens on a misbehaving upstream).

For the full threat model — what is protected, what is not, and how to respond
to a suspected leak — see [THREAT_MODEL.md](./THREAT_MODEL.md).

Audit a machine's cache state at any time:

```bash
python -m scmaine_tokens.doctor
# or, after install:
scmaine-tokens-doctor
```

Exit code 0 on clean state, 1 on any issue (stale lock, expired token, wrong
permissions, missing env var). Token values are NEVER printed — only
`<redacted, len=N>` placeholders.

## Adding a new service

1. Copy `src/scmaine_tokens/guesty.py` (for OAuth client_credentials) or
   `src/scmaine_tokens/breezeway.py` (for refresh-token rotation).
2. Define the cache path as `_resolve_cache_dir() / "<service>.json"`.
3. Export `get_<service>_token` from `src/scmaine_tokens/__init__.py`.
4. Add tests in `tests/test_<service>.py` following the existing pattern.
5. Add the required env vars to this README.
