# Native environment

`dependencies.json` pins the ordinary ML-DSA backend source, archive checksums and
build flags. Run `.venv/bin/python scripts/build_native.py` from the project root.
Builds use two jobs and install only into ignored `.deps/install`.

The C/C++ target checks compiler/linker operation and the installed library's ML-DSA-65
metadata/context support. Real signing and rejection tests live in `tests/smoke/`.
No authentication relation, bounded verifier or proof circuit is implemented here.

See [the environment record](../docs/environment.md) for exact versions and commands.
