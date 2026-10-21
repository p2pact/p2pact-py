"""Compression (spec §5): zstd with a dictionary. A compressed message is
[dictionary slot 1][zstd frame without its magic and dictionary id]; slot 0 — no dictionary.
The slot is the dictionary's place in the sender's list for this receiver."""
import os

import zstandard

from .crypto import blake2s

ZIP_MIN = 64
ZIP_FAST_FROM = 32 << 10
# shorter messages are compressed at the fastest level when there is a dictionary (most chat
# messages): with one it loses only a few percent of bytes
ZIP_QUICK_BELOW = 1 << 10
DICT_KEEP = 4  # dictionaries kept of one kind: common, ours for a device, a device's own
SLOTS_MAX = 32  # past this many slots, a new dictionary takes the oldest empty one
MAGIC = b"\x28\xb5\x2f\xfd"

LEVEL_PLAIN, LEVEL_DICT, LEVEL_FAST, LEVEL_QUICK = 19, 7, 3, 1


def dict_id(raw: bytes) -> bytes:
    return blake2s(raw)[:16]


class Dict:
    """A dictionary; peer "" — a common one, anyone may have it; otherwise it belongs to the
    pair with that device and is never shown or given to another. own: we trained it (for peer)."""

    def __init__(self, raw: bytes, peer: str = "", own: bool = False):
        self.raw = bytes(raw)
        self.id = dict_id(self.raw)
        self.zd = zstandard.ZstdCompressionDict(self.raw)
        self.zid = self.zd.dict_id()
        self.peer, self.own = peer, own
        self._enc: dict[int, zstandard.ZstdCompressor] = {}
        self._dec = None

    def visible(self, peer: str) -> bool:
        """Whether it may be used with, listed to or given to peer."""
        return self.peer == "" or self.peer == peer

    def compressor(self, level: int):
        c = self._enc.get(level)
        if c is None:
            c = self._enc[level] = _compressor(self, level)
        return c

    def decompressor(self):
        if self._dec is None:
            self._dec = zstandard.ZstdDecompressor(dict_data=self.zd)
        return self._dec


def _compressor(d, level):
    return zstandard.ZstdCompressor(level=level, dict_data=d.zd if d else None, write_checksum=False,
                                    write_content_size=True)


_plain = {}


def compress(msg: bytes, d: Dict | None, slot: int) -> bytes | None:
    if len(msg) < ZIP_MIN:
        return None
    try:
        if d is None:
            level = LEVEL_FAST if len(msg) >= ZIP_FAST_FROM else LEVEL_PLAIN
            if level not in _plain:
                _plain[level] = _compressor(None, level)
            c = _plain[level]
        else:
            # not the best level: with a dictionary it costs many times the time for a few percent
            c = d.compressor(LEVEL_FAST if len(msg) >= ZIP_FAST_FROM else
                             LEVEL_QUICK if len(msg) < ZIP_QUICK_BELOW else LEVEL_DICT)
        frame = strip_frame(c.compress(msg))
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
    dz = d.decompressor() if d else zstandard.ZstdDecompressor()
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


def write_atomic(path: str, b: bytes):
    tmp = path + ".tmp"  # replaced in one step: never read half-written
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(b)
    os.replace(tmp, path)


class DictStore:
    """Dictionaries in dir/net-dicts/<id hex>; the order (newest first) is in the file "order",
    a line per dictionary: "<id hex>" for a common one, "<id hex> <device> own|their" for a
    pair's (the same files as the Go implementation)."""

    def __init__(self, dir_: str):
        self.dir = os.path.join(dir_, "net-dicts")
        self.dicts: list[Dict] = []  # newest first
        # what we list to each device, by slot. A dictionary keeps its slot while listed (a
        # message compressed with it may still be on its way on another stream, behind the new
        # list); a dropped one leaves an empty id, and a new one goes to the end.
        self.slots: dict[str, list[bytes]] = {}
        self.gen = 0  # bumped on every change of the dictionaries
        self.cache: dict[str, tuple[int, list[bytes]]] = {}
        try:
            lines = open(os.path.join(self.dir, "order")).read().split("\n")
        except OSError:
            return
        for line in lines:
            f = line.split()
            if len(f) not in (1, 3):  # a damaged line: never take a pair's dictionary for a common one
                continue
            try:
                d = Dict(open(os.path.join(self.dir, f[0]), "rb").read())
            except (OSError, zstandard.ZstdError):
                continue
            if d.id.hex() != f[0]:
                continue
            if len(f) == 3:
                d.peer, d.own = f[1], f[2] == "own"
            self.dicts.append(d)

    def get(self, id_: bytes, peer: str) -> Dict | None:
        """Dictionary id_ if peer may see it."""
        return next((d for d in self.dicts if d.id == id_ and d.visible(peer)), None)

    def add(self, d: Dict):
        """Puts a dictionary first (moving it up if known) and deletes the oldest extra ones of
        its kind."""
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        with open(os.open(os.path.join(self.dir, d.id.hex()), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
            f.write(d.raw)
        out, dropped = [d], []
        kinds = {(d.peer, d.own): 1}
        for x in self.dicts:
            if x.id == d.id and x.peer == d.peer:
                continue
            k = (x.peer, x.own)
            kinds[k] = kinds.get(k, 0) + 1
            (dropped if kinds[k] > DICT_KEEP else out).append(x)
        for x in dropped:
            if not _listed(out, x.id):  # one file serves the same bytes kept as another kind
                try:
                    os.remove(os.path.join(self.dir, x.id.hex()))
                except OSError:
                    pass
        self.dicts = out
        self.gen += 1
        self._save_order()

    def _save_order(self):
        """Through a temporary file: a torn one could turn a pair's dictionary into a common
        one (though loading skips damaged lines too)."""
        lines = [x.id.hex() + (f" {x.peer} {'own' if x.own else 'their'}" if x.peer else "") for x in self.dicts]
        write_atomic(os.path.join(self.dir, "order"), ("\n".join(lines) + "\n").encode())

    def list(self, peer: str) -> list[Dict]:
        """What peer sees of our dictionaries, newest first: the common ones and the pair's."""
        out = []
        for d in self.dicts:
            if d.visible(peer) and not _listed(out, d.id):
                out.append(d)
        return out

    def ids(self, peer: str) -> list[bytes]:
        """Our list for peer, by slot (an empty id — a free slot)."""
        return list(self._slots_for(peer))

    def _slots_for(self, peer: str) -> list[bytes]:
        c = self.cache.get(peer)
        if c and c[0] == self.gen:
            return c[1]
        lst = self.list(peer)
        slots = self.slots.get(peer, [])
        for i, id_ in enumerate(slots):
            if id_ and not _listed(lst, id_):
                slots[i] = b""
        for d in reversed(lst):  # the oldest first, so the newest gets the last slot
            if d.id in slots:
                continue
            free = -1
            if len(slots) >= SLOTS_MAX:
                free = next((i for i, id_ in enumerate(slots) if not id_), -1)
            if free < 0:
                slots.append(d.id)
            else:
                slots[free] = d.id
        self.slots[peer] = slots
        self.cache[peer] = (self.gen, slots)
        return slots

    def slot_of(self, peer: str, d: Dict) -> int:
        """d's slot in our list for peer (from 1)."""
        slots = self._slots_for(peer)
        return slots.index(d.id) + 1 if d.id in slots else 0

    def own(self, peer: str) -> Dict | None:
        """Our newest dictionary trained for peer."""
        return next((d for d in self.dicts if d.own and d.peer == peer), None)

    def pick(self, peer: str, theirs: list[bytes], lacks: list[bytes]):
        """The dictionary to compress for peer and its slot in our list for it: ours trained for
        it if it has it, else the newest it also has. Nothing in common: (None, 0)."""
        lst = self.list(peer)
        ok = lambda d: d.id in theirs and d.id not in lacks
        for d in lst:
            if d.own and ok(d):
                return d, self.slot_of(peer, d)
        for d in lst:
            if ok(d):
                return d, self.slot_of(peer, d)
        return None, 0

    def forget(self, peer: str):
        """Drops what belongs to the pair with peer: our dictionaries for it and its own."""
        keep = [d for d in self.dicts if d.peer != peer]
        drop = [d for d in self.dicts if d.peer == peer]
        self.slots.pop(peer, None)
        self.cache.pop(peer, None)
        if not drop:
            return
        self.dicts = keep
        for d in drop:
            if not _listed(keep, d.id):
                try:
                    os.remove(os.path.join(self.dir, d.id.hex()))
                except OSError:
                    pass
        self.gen += 1
        try:
            self._save_order()
        except OSError:
            pass


def _listed(lst: list[Dict], id_: bytes) -> bool:
    return any(d.id == id_ for d in lst)
