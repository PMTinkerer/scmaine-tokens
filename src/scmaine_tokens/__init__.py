"""scmaine-tokens — shared OAuth token broker for the SCMaine workspace.

Public API::

    from scmaine_tokens import (
        get_guesty_token, get_breezeway_token, get_notion_token,
        TokenBrokerError, ConfigurationError, TokenFetchError, RateLimitedError,
    )

Why this exists
---------------
- Guesty: hard limit of 5 OAuth token requests per 24 hours per client_id.
  Without a shared broker, multiple tools refreshing independently can blow
  through the budget fast.
- Breezeway: ~1 auth request per minute rate limit. Same blast-radius risk.
- Notion: static integration token (no rotation), but exposed through this
  package to give consumers a uniform ``get_*_token()`` interface.

All tokens are cached in ``~/.cache/scmaine-tokens/`` (override with
``SCMAINE_TOKENS_CACHE_DIR``). Cache files are chmod 600.
"""

from scmaine_tokens.breezeway import get_breezeway_token
from scmaine_tokens.errors import (
    ConfigurationError,
    RateLimitedError,
    TokenBrokerError,
    TokenFetchError,
)
from scmaine_tokens.guesty import get_guesty_token
from scmaine_tokens.notion import get_notion_token

__version__ = "0.1.0"

__all__ = [
    "get_guesty_token",
    "get_breezeway_token",
    "get_notion_token",
    "TokenBrokerError",
    "ConfigurationError",
    "TokenFetchError",
    "RateLimitedError",
]
