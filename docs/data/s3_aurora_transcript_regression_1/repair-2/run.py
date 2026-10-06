import json
import lzma
from pathlib import Path

exec(
    compile(
        json.loads(lzma.decompress(Path(__file__).with_name("evidence.json.xz").read_bytes()))[
            "source"
        ],
        __file__,
        "exec",
    )
)
