"""Atomic file cache with advisory locking. POSIX-only (macOS, Linux)."""

import fcntl
import json
import os
import pathlib
import tempfile
import time
from contextlib import contextmanager
from typing import Any, Iterator, Optional


def _resolve_cache_dir() -> pathlib.Path:
    """Return the cache directory, creating it if needed.

    Reads SCMAINE_TOKENS_CACHE_DIR env var; falls back to
    ~/.cache/scmaine-tokens/.
    """
    env = os.environ.get("SCMAINE_TOKENS_CACHE_DIR")
    if env:
        path = pathlib.Path(env).expanduser()
    else:
        path = pathlib.Path.home() / ".cache" / "scmaine-tokens"
    path.mkdir(parents=True, exist_ok=True)
    # Defense-in-depth: lock the directory down to owner-only so even
    # `ls` from another user can't enumerate cached source names.
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


class FileCache:
    """An atomic, lockable JSON file cache.

    Use within a ``with cache.lock():`` context to serialize concurrent access.
    Reads via ``.read()``, writes via ``.write()``. Writes go through a temp
    file + os.replace for crash-safety.
    """

    def __init__(self, path: pathlib.Path) -> None:
        self._path = path
        self._lock_path = path.with_suffix(path.suffix + ".lock")

    @contextmanager
    def lock(self, timeout_s: float = 30.0) -> Iterator[None]:
        """Acquire an exclusive advisory file lock. Released on context exit.

        Blocks up to ``timeout_s`` seconds; raises TimeoutError on timeout.
        Uses a separate .lock file so reads/writes to the cache path are
        unaffected by the lock fd.
        """
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._lock_path.parent, 0o700)
        except OSError:
            pass
        fd = os.open(str(self._lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + timeout_s
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        raise TimeoutError(
                            f"Could not acquire lock on {self._lock_path} "
                            f"within {timeout_s}s"
                        )
                    time.sleep(0.1)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def read(self) -> Optional[dict]:
        """Read and parse the cache. Returns None if missing / unreadable / not a dict."""
        if not self._path.exists():
            return None
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return None
            return data
        except (json.JSONDecodeError, OSError):
            return None

    def write(self, data: dict) -> None:
        """Atomically write JSON. Caller must hold the lock."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:
            pass
        # tempfile in same directory so os.replace is atomic (same filesystem)
        fd, tmp_path = tempfile.mkstemp(
            prefix=self._path.name + ".",
            suffix=".tmp",
            dir=str(self._path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            # Atomic on POSIX
            os.replace(tmp_path, self._path)
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
