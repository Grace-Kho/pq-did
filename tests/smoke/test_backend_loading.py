"""The project loader must fail before upstream can attempt runtime installation."""

import importlib

import pytest

from pqdid import backend


def test_missing_library_does_not_import_upstream(tmp_path, monkeypatch):
    def unexpected_import(_name):
        pytest.fail("Upstream must not be imported when the local library is missing")

    monkeypatch.setattr(backend, "LIBRARY", tmp_path / "missing.so")
    monkeypatch.setattr(importlib, "import_module", unexpected_import)
    with pytest.raises(RuntimeError, match="Local liboqs is missing"):
        backend.load_backend()


def test_unloadable_library_does_not_import_upstream(tmp_path, monkeypatch):
    invalid_library = tmp_path / "invalid.so"
    invalid_library.write_bytes(b"not a shared library")

    def unexpected_import(_name):
        pytest.fail("Upstream must not be imported when the local library cannot load")

    monkeypatch.setattr(backend, "LIBRARY", invalid_library)
    monkeypatch.setattr(importlib, "import_module", unexpected_import)
    with pytest.raises(RuntimeError, match="Cannot load local liboqs"):
        backend.load_backend()
