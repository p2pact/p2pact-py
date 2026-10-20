"""A small CBOR (RFC 8949) codec for P2PACT messages: integers, bytes, text, lists, dicts,
booleans, None and floats, shortest forms when encoding."""
import struct


class Raw(bytes):
    """An already-encoded CBOR item, inserted as is."""


def _head(out: bytearray, major: int, n: int) -> None:
    m = major << 5
    if n < 24:
        out.append(m | n)
    elif n < 0x100:
        out += bytes((m | 24, n))
    elif n < 0x10000:
        out.append(m | 25)
        out += struct.pack(">H", n)
    elif n < 0x100000000:
        out.append(m | 26)
        out += struct.pack(">I", n)
    else:
        out.append(m | 27)
        out += struct.pack(">Q", n)


def _write(out: bytearray, v) -> None:
    if isinstance(v, Raw):
        out += v
    elif v is None:
        out.append(0xF6)
    elif v is False:
        out.append(0xF4)
    elif v is True:
        out.append(0xF5)
    elif isinstance(v, int):
        _head(out, 0, v) if v >= 0 else _head(out, 1, -1 - v)
    elif isinstance(v, float):
        out.append(0xFB)
        out += struct.pack(">d", v)
    elif isinstance(v, str):
        b = v.encode()
        _head(out, 3, len(b))
        out += b
    elif isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        _head(out, 2, len(b))
        out += b
    elif isinstance(v, (list, tuple)):
        _head(out, 4, len(v))
        for x in v:
            _write(out, x)
    elif isinstance(v, dict):
        _head(out, 5, len(v))
        for k, x in v.items():
            _write(out, k)
            _write(out, x)
    else:
        raise TypeError(f"cbor: cannot encode {type(v)}")


def encode(v) -> bytes:
    out = bytearray()
    _write(out, v)
    return bytes(out)


class _Reader:
    def __init__(self, b: bytes):
        self.b, self.pos = b, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.b):
            raise ValueError("cbor: truncated")
        v = self.b[self.pos:self.pos + n]
        self.pos += n
        return v

    def arg(self, info: int) -> int:
        if info < 24:
            return info
        size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
        if size is None:
            raise ValueError("cbor: indefinite lengths are not supported")
        return int.from_bytes(self.take(size), "big")

    def item(self):
        ib = self.take(1)[0]
        major, info = ib >> 5, ib & 31
        if major == 0:
            return self.arg(info)
        if major == 1:
            return -1 - self.arg(info)
        if major == 2:
            return self.take(self.arg(info))
        if major == 3:
            return self.take(self.arg(info)).decode()
        if major == 4:
            return [self.item() for _ in range(self.arg(info))]
        if major == 5:
            d = {}
            for _ in range(self.arg(info)):
                k = self.item()
                d[k if not isinstance(k, list) else tuple(k)] = self.item()
            return d
        if major == 6:
            self.arg(info)
            return self.item()
        if info == 20:
            return False
        if info == 21:
            return True
        if info in (22, 23):
            return None
        if info == 25:
            return struct.unpack(">e", self.take(2))[0]
        if info == 26:
            return struct.unpack(">f", self.take(4))[0]
        if info == 27:
            return struct.unpack(">d", self.take(8))[0]
        raise ValueError(f"cbor: unsupported item {ib:#x}")

    def skip(self) -> bytes:
        start = self.pos
        self.item()
        return self.b[start:self.pos]


def decode(b: bytes):
    r = _Reader(bytes(b))
    v = r.item()
    if r.pos != len(r.b):
        raise ValueError("cbor: trailing bytes")
    return v


def decode_array_raw(b: bytes) -> list:
    """Splits a top-level CBOR array into its elements' encoded bytes."""
    r = _Reader(bytes(b))
    ib = r.take(1)[0]
    if ib >> 5 != 4:
        raise ValueError("cbor: not an array")
    out = [r.skip() for _ in range(r.arg(ib & 31))]
    if r.pos != len(r.b):
        raise ValueError("cbor: trailing bytes")
    return out
