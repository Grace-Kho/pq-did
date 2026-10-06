"""Select official byte-oriented NIST CAVP records, without production imports.

Run with the downloaded archive directory and an explicit new fixture output path.
Archives are checked before extracting selected records; no network or hash oracle.
"""

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

BASE = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/"
ARCHIVES = {
    "sha-3bytetestvectors.zip": "cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c",
    "shakebytetestvectors.zip": "debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7",
}


def extract(directory):
    sources, cases = [], []
    for archive, digest in ARCHIVES.items():
        path = directory / archive
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("NIST archive digest mismatch")
        with zipfile.ZipFile(path) as bundle:
            algorithms = (
                [("SHA3_384", 104)]
                if archive.startswith("sha-3")
                else [("SHAKE128", 168), ("SHAKE256", 136)]
            )
            for algorithm, rate in algorithms:
                name = algorithm + "ShortMsg.rsp"
                raw = bundle.read(name)
                text = raw.decode("ascii")
                output_bits = (
                    384
                    if algorithm == "SHA3_384"
                    else int(re.search(r"\[Outputlen = (\d+)\]", text)[1])
                )
                sources.append(
                    {
                        "archive_url": BASE + archive,
                        "archive_sha256": digest,
                        "member": name,
                        "member_sha256": hashlib.sha256(raw).hexdigest(),
                        "header": text.split("[")[0].strip(),
                    }
                )
                for match in re.finditer(
                    r"Len = (\d+)\s+Msg = ([0-9a-f]+)\s+(?:MD|Output) = ([0-9a-f]+)", text
                ):
                    length = int(match[1])
                    if length // 8 not in (0, 1, rate - 1, rate, rate + 1):
                        continue
                    cases.append(
                        {
                            "algorithm": algorithm,
                            "source": name,
                            "length_bits": length,
                            "message": "" if length == 0 else match[2],
                            "source_msg": match[2],
                            "output_bits": output_bits,
                            "output": match[3],
                        }
                    )
            if archive.startswith("sha-3"):
                name = "SHA3_384LongMsg.rsp"
                raw = bundle.read(name)
                text = raw.decode("ascii")
                match = re.search(r"Len = (\d+)\s+Msg = ([0-9a-f]+)\s+MD = ([0-9a-f]+)", text)
                sources.append(
                    {
                        "archive_url": BASE + archive,
                        "archive_sha256": digest,
                        "member": name,
                        "member_sha256": hashlib.sha256(raw).hexdigest(),
                        "header": text.split("[")[0].strip(),
                    }
                )
                cases.append(
                    {
                        "algorithm": "SHA3_384",
                        "source": name,
                        "length_bits": int(match[1]),
                        "message": match[2],
                        "source_msg": match[2],
                        "output_bits": 384,
                        "output": match[3],
                    }
                )
    return {
        "source": "NIST CAVP CAVS 19.0, January 2016; informal checks, not CAVP validation",
        "selection": "Short 0/1/rate-1/rate/(rate+1 where present); first SHA3-384 long record",
        "extractor_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "sources": sources,
        "cases": cases,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.directory), indent=2) + "\n")
