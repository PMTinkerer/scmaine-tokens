"""Unit tests for _cache.py."""

import pathlib
import stat
import threading
import time

import pytest

from scmaine_tokens._cache import FileCache


def make_cache(tmp_path: pathlib.Path, name: str = "test.json") -> FileCache:
    return FileCache(tmp_path / name)


class TestReadWrite:
    def test_write_then_read_roundtrips(self, tmp_path):
        cache = make_cache(tmp_path)
        with cache.lock():
            cache.write({"x": 1})
        result = cache.read()
        assert result == {"x": 1}

    def test_read_returns_none_for_missing_file(self, tmp_path):
        cache = make_cache(tmp_path)
        assert cache.read() is None

    def test_read_returns_none_for_corrupt_json(self, tmp_path):
        cache = make_cache(tmp_path)
        cache_path = tmp_path / "test.json"
        cache_path.write_text("not valid json{{{", encoding="utf-8")
        assert cache.read() is None

    def test_read_returns_none_for_non_dict(self, tmp_path):
        """A JSON list is valid JSON but not a dict — should return None."""
        cache = make_cache(tmp_path)
        cache_path = tmp_path / "test.json"
        cache_path.write_text("[1, 2, 3]", encoding="utf-8")
        assert cache.read() is None

    def test_atomic_write_no_tmp_files_left_after_success(self, tmp_path):
        cache = make_cache(tmp_path)
        with cache.lock():
            cache.write({"key": "value"})
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == [], f"Unexpected .tmp files: {tmp_files}"

    def test_chmod_600(self, tmp_path):
        cache = make_cache(tmp_path)
        with cache.lock():
            cache.write({"secret": "token123"})
        mode = stat.S_IMODE((tmp_path / "test.json").stat().st_mode)
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"


class TestLocking:
    def test_lock_serializes_concurrent_writers(self, tmp_path):
        """Two threads taking the lock must not interleave writes."""
        cache = make_cache(tmp_path)
        results = []
        errors = []

        def writer(value: int) -> None:
            try:
                with cache.lock():
                    current = cache.read() or {"count": 0}
                    # Small sleep inside the lock to make races more visible.
                    time.sleep(0.05)
                    current["count"] += value
                    cache.write(current)
                    results.append(current["count"])
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=writer, args=(1,))
        t2 = threading.Thread(target=writer, args=(10,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert errors == [], f"Thread errors: {errors}"
        # Both writers ran; final count must be exactly 11.
        final = cache.read()
        assert final is not None
        assert final["count"] == 11, f"Race detected, count={final['count']}"
        # The two intermediate results must be 1 and 11 (or 10 and 11), never
        # overlapping — their sum must equal 11.
        assert sorted(results) == sorted(set(results)), "Duplicate intermediate result"

    def test_lock_timeout(self, tmp_path):
        """A thread holding the lock causes a second caller to timeout."""
        cache = make_cache(tmp_path)
        lock_held = threading.Event()
        lock_released = threading.Event()

        def hold_lock() -> None:
            with cache.lock():
                lock_held.set()
                lock_released.wait(timeout=5.0)

        holder = threading.Thread(target=hold_lock)
        holder.start()
        lock_held.wait(timeout=5.0)

        try:
            with pytest.raises(TimeoutError):
                with cache.lock(timeout_s=0.5):
                    pass
        finally:
            lock_released.set()
            holder.join()
