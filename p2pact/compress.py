"""Compression (spec §5): zstd with a dictionary. A compressed message is
[dictionary slot 1][zstd frame without its magic and dictionary id]; slot 0 — no dictionary."""
import os

import zstandard

from .crypto import blake2s

ZIP_MIN = 64
ZIP_FAST_FROM = 32 << 10
DICT_KEEP = 4
MAGIC = b"\x28\xb5\x2f\xfd"


def dict_id(raw: bytes) -> bytes:
    return blake2s(raw)[:16]


class Dict:
    def __init__(self, raw: bytes):
        self.raw = bytes(raw)
        self.id = dict_id(self.raw)
        self.zd = zstandard.ZstdCompressionDict(self.raw)
        self.zid = self.zd.dict_id()


def _compressor(d, level):
    return zstandard.ZstdCompressor(level=level, dict_data=d.zd if d else None, write_checksum=False,
                                    write_content_size=True)


def compress(msg: bytes, d: Dict | None, slot: int) -> bytes | None:
    if len(msg) < ZIP_MIN:
        return None
    level = 3 if len(msg) >= ZIP_FAST_FROM else 19
    try:
        frame = strip_frame(_compressor(d, level).compress(msg))
    except zstandard.ZstdError:
        return None
    if frame is None or 1 + len(frame) >= len(msg):
        return None
    return bytes((slot,)) + frame


def decompress(b: bytes, d: Dict | None, max_size: int) -> bytes:
    if len(b) < 2:
        raise ValueError("short")
    frame = restore_frame(b[1:], d.zid if d else 0)
    if frame is None:
        raise ValueError("bad frame")
    dz = zstandard.ZstdDecompressor(dict_data=d.zd if d else None)
    return dz.decompress(frame, max_output_size=max_size)


def strip_frame(f: bytes) -> bytes | None:
    if len(f) < 6 or f[:4] != MAGIC:
        return None
    f = f[4:]
    fhd = f[0]
    did = (0, 1, 2, 4)[fhd & 3]
    at = 1 if fhd & 0x20 else 2
    if len(f) < at + did:
        return None
    return bytes((fhd & ~3 & 0xFF,)) + f[1:at] + f[at + did:]


def restore_frame(f: bytes, zid: int) -> bytes | None:
    if len(f) < 2 or f[0] & 3:
        return None
    fhd = f[0]
    at = 1 if fhd & 0x20 else 2
    if len(f) < at:
        return None
    if zid == 0:
        return MAGIC + f
    return MAGIC + bytes((fhd | 3,)) + f[1:at] + zid.to_bytes(4, "little") + f[at:]


class DictStore:
    """Dictionaries in dir/net-dicts/<id hex>, newest first in "order"."""

    def __init__(self, dir_: str):
        self.dir = os.path.join(dir_, "net-dicts")
        self.dicts: list[Dict] = []
        try:
            order = open(os.path.join(self.dir, "order")).read().split()
        except OSError:
            return
        for h in order:
            try:
                d = Dict(open(os.path.join(self.dir, h), "rb").read())
                if d.id.hex() == h:
                    self.dicts.append(d)
            except (OSError, zstandard.ZstdError):
                pass

    def get(self, id_: bytes) -> Dict | None:
        return next((d for d in self.dicts if d.id == id_), None)

    def add(self, d: Dict):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        with open(os.path.join(self.dir, d.id.hex()), "wb") as f:
            f.write(d.raw)
        out = [d] + [x for x in self.dicts if x.id != d.id]
        for x in out[DICT_KEEP:]:
            try:
                os.remove(os.path.join(self.dir, x.id.hex()))
            except OSError:
                pass
        self.dicts = out[:DICT_KEEP]
        with open(os.path.join(self.dir, "order"), "w") as f:
            f.write("\n".join(x.id.hex() for x in self.dicts) + "\n")

    def ids(self) -> list[bytes]:
        return [d.id for d in self.dicts]

    def pick(self, theirs: list[bytes], lacks: list[bytes]):
        for i, d in enumerate(self.dicts):
            if d.id in theirs and d.id not in lacks:
                return d, i + 1
        return None, 0
