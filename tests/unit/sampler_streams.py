"""Artificial sampler inputs ONLY, not cryptographic SHAKE/signature vectors."""


class CountingReader:
    def __init__(self, data: bytes):
        self.data = data
        self.consumed = 0
        self.requests = []

    def read(self, length: int) -> bytes:
        self.requests.append(length)
        result = self.data[self.consumed : self.consumed + length]
        self.consumed += length
        assert len(result) == length, "test stream unexpectedly depleted"
        return result


def ntt_stream(rejections: int) -> bytes:
    # 0xffffff is rejected after high-bit masking; accepted coefficients are 0..255.
    return b"\xff\xff\xff" * rejections + b"".join(i.to_bytes(3, "little") for i in range(256))


def ball_stream(rejections: int) -> bytes:
    # Reject 255 at i=207; then accept j=i for each coefficient. First sign is -1.
    return b"\x01" + bytes(7) + b"\xff" * rejections + bytes(range(207, 256))
