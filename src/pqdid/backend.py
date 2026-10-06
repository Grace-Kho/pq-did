"""Load ordinary ML-DSA library operations for environment checks only.

This is not the manuscript's bounded verifier, authentication relation or proof system.
Always import the binding through this loader: upstream's direct ``import oqs`` may
download and compile liboqs if it cannot find a shared library.
"""

import ctypes
import importlib
import importlib.metadata
import os
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
NATIVE_PREFIX = ROOT / "native/.deps/install"
LIBRARY = NATIVE_PREFIX / "lib/liboqs.so"
VERSION = "0.16.0"


def load_backend() -> ModuleType:
    """Require the local shared library before importing the upstream binding."""
    if not LIBRARY.is_file():
        raise RuntimeError("Local liboqs is missing. Run: .venv/bin/python scripts/build_native.py")
    try:
        library = ctypes.CDLL(str(LIBRARY))
    except OSError as error:
        raise RuntimeError(f"Cannot load local liboqs: {LIBRARY}") from error
    library.OQS_version.restype = ctypes.c_char_p
    if library.OQS_version().decode("ascii") != VERSION:
        raise RuntimeError("Unexpected native liboqs version; rebuild the pinned source.")
    if importlib.metadata.version("liboqs-python") != VERSION:
        raise RuntimeError("Unexpected liboqs-python version; run bash scripts/setup.sh.")
    os.environ["OQS_INSTALL_PATH"] = str(NATIVE_PREFIX)
    binding = importlib.import_module("oqs")
    # Upstream searches system locations too; fail if a different library wins.
    if Path(binding.native()._name).resolve() != LIBRARY.resolve():
        raise RuntimeError("liboqs-python loaded a different library from the pinned local build.")
    if binding.oqs_version() != VERSION or not binding.sig_supports_context("ML-DSA-65"):
        raise RuntimeError("The pinned ML-DSA-65 context API is unavailable.")
    return binding
