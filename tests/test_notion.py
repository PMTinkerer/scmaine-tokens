"""Unit tests for notion.py."""

import pytest

from scmaine_tokens.errors import ConfigurationError
from scmaine_tokens.notion import get_notion_token


class TestGetNotionToken:
    def test_returns_token_when_env_set(self, monkeypatch):
        monkeypatch.setenv("NOTION_TOKEN", "secret_abc123")
        assert get_notion_token() == "secret_abc123"

    def test_raises_when_env_missing(self, monkeypatch):
        monkeypatch.delenv("NOTION_TOKEN", raising=False)
        with pytest.raises(ConfigurationError, match="NOTION_TOKEN"):
            get_notion_token()

    def test_custom_env_var_name(self, monkeypatch):
        monkeypatch.setenv("MY_NOTION_KEY", "custom_key_xyz")
        assert get_notion_token(env_var="MY_NOTION_KEY") == "custom_key_xyz"

    def test_raises_for_custom_env_var_when_missing(self, monkeypatch):
        monkeypatch.delenv("MY_NOTION_KEY", raising=False)
        with pytest.raises(ConfigurationError, match="MY_NOTION_KEY"):
            get_notion_token(env_var="MY_NOTION_KEY")
