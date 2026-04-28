"""Notion integration token. Static — no caching, no rotation."""

import os
from typing import Optional

from scmaine_tokens.errors import ConfigurationError


def get_notion_token(*, env_var: str = "NOTION_TOKEN") -> str:
    """Return the Notion integration token from env. Raises if unset.

    Notion integration tokens are static (no expiry, no rotation). This
    function exists to give callers a uniform interface matching
    get_guesty_token / get_breezeway_token.
    """
    token = os.environ.get(env_var)
    if not token:
        raise ConfigurationError(f"{env_var} must be set")
    return token
