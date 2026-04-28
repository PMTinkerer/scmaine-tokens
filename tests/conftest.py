import os
import pathlib
import tempfile

import pytest


@pytest.fixture
def tmp_cache_dir(monkeypatch, tmp_path):
    """Isolate every test in its own cache directory."""
    monkeypatch.setenv("SCMAINE_TOKENS_CACHE_DIR", str(tmp_path))
    return tmp_path
