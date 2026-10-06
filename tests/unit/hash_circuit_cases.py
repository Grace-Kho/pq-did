"""Private-input circuit comparisons against independent supplied digest bytes."""

import hashlib

from pqdid.circuits.emitter import Emitter, Limits
from pqdid.circuits.keccak import sha3_384, shake128, shake256
from pqdid.circuits.parsing import equal_bytes, public_bytes

FUNCTIONS = {"SHA3_384": sha3_384, "SHAKE128": shake128, "SHAKE256": shake256}
ORACLES = {
    "SHA3_384": hashlib.sha3_384,
    "SHAKE128": hashlib.shake_128,
    "SHAKE256": hashlib.shake_256,
}


def digest(algorithm, message, length):
    native = ORACLES[algorithm](message)
    return native.digest() if algorithm == "SHA3_384" else native.digest(length)


def hash_predicate(
    algorithm, length, expected, *, limits=None, mode="materialised", sink=None, prefix=b""
):
    e = Emitter(
        length * 8,
        limits=limits or Limits(),
        mode=mode,
        sink=sink,
        public_data=algorithm.encode() + len(prefix).to_bytes(4, "big") + prefix + expected,
    )
    message = public_bytes(e, prefix) + e.inputs
    function = FUNCTIONS[algorithm]
    output = (
        function(e, message) if algorithm == "SHA3_384" else function(e, message, len(expected))
    )
    return e.finish(equal_bytes(e, output, public_bytes(e, expected)))
