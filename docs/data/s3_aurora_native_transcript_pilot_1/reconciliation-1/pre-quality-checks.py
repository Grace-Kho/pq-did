"""Dispatch bounded native work; preservation completion is appended before audit."""

from pathlib import Path
import types

R = Path(__file__).resolve().parent


def run(name):
    path = R / "native_work.py"
    m = types.ModuleType("native_work")
    m.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), m.__dict__)
    if name.startswith("build-"):
        m.build(name)
    elif name == "cases":
        m.cases()
    else:
        raise RuntimeError("completion workflow not yet selected")
