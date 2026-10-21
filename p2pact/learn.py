"""Our own dictionaries (spec §5): a device trains a dictionary for each device it talks to, on
that conversation, so the dictionary shows the other side nothing it has not already seen. It
learns what it sent; while that is little, what it got fills the history up to 256 KB (it helps
then, and stops helping once there is enough of our own). The first dictionary comes at 32 KB of
history; then a new one when the history has doubled (up to 1 MB), monthly, or when compression
got 15 % worse than right after training. The node (node.py) queues messages and decides when;
this module keeps the history and trains."""
import os
import random
from collections import deque

import zstandard

from .compress import Dict, write_atomic
from .crypto import blake2s

LEARN_FIRST = 32 << 10  # history to train the first dictionary on
LEARN_MAX = 1 << 20  # our messages kept: the newest
LEARN_HEARD = 256 << 10  # the received ones fill the history up to this
LEARN_SAMPLE = 4 << 10  # a message is cut to this: a dictionary helps its start most
LEARN_WINDOW = 32 << 10  # bytes sent to measure compression over
LEARN_WORSE = 1.15  # retrain when compression is this much worse than the first window
LEARN_MONTH = 30 * 24 * 3600.0
LEARN_DICT_MAX = 64 << 10
LEARN_QUEUE_MAX = 1 << 20  # bytes waiting for the history; past it messages are skipped
LEARN_OWN_MIN = 8  # fewer own messages worth compressing: no dictionary of our own

# Learning is deferred: sending and receiving only queue the message. Once a second the queue
# goes into the history in one go, off the sending path, and training waits for a lull in the
# conversation: the first dictionaries by the history's size, the monthly and the 15 % checks
# once a day.
LEARN_TICK = 1.0
LEARN_LULL = 1.0  # no messages with the device for this long: time to train
LEARN_WAIT = 60.0  # or train anyway after waiting this long for a lull
LEARN_CHECK = 24 * 3600.0  # how often the monthly and the 15 % checks run


def history_path(dir_: str, peer: str) -> str:
    return os.path.join(dir_, "net-history", blake2s(peer.encode())[:8].hex())


def _record(m: bytes, heard: bool) -> bytes:
    """A message in the file: [length 4][1 — received, 0 — sent][bytes] (as p2pact-go)."""
    return len(m).to_bytes(4, "big") + (b"\x01" if heard else b"\x00") + m


class History:
    """One conversation, kept in dir/net-history/<hash of the device's address>."""

    def __init__(self, path: str):
        self.path = path
        self.file_size = 0
        self.buf = bytearray()  # records not yet written
        self.rewrite = False  # the file has outgrown the history: write it anew
        self.gone = False  # the device was forgotten: write nothing more
        self.own: deque[bytes] = deque()
        self.heard: deque[bytes] = deque()
        self.own_size = self.heard_size = 0
        self.trained = 0  # history size when the current dictionary was trained
        self.at = 0.0  # when it was trained
        self.plain = self.zips = 0  # compression with the current dictionary over the current window
        self.base = 0.0  # and over the first window after training
        self.worse = False  # a window came out 15 % worse than the first
        self.checked = 0.0  # the last monthly and 15 % check
        self.due = ""  # a new dictionary is due ("" — not), waiting for a lull since due_at
        self.due_at = 0.0
        self.training = False

    @staticmethod
    def load(path: str) -> "History":
        h = History(path)
        try:
            b = open(path, "rb").read()
        except OSError:
            b = b""
        h.file_size = len(b)
        at = 0
        while len(b) - at >= 5:
            n = int.from_bytes(b[at:at + 4], "big")
            if n > LEARN_SAMPLE or len(b) - at < 5 + n or b[at + 4] > 1:  # a torn record: the rest is lost
                break
            h.add(b[at + 5:at + 5 + n], b[at + 4] == 1)
            at += 5 + n
        return h

    def size(self) -> int:
        """How much the next dictionary would be trained on."""
        return self.own_size + min(self.heard_size, max(0, LEARN_HEARD - self.own_size))

    def add(self, m: bytes, heard: bool):
        m = m[:LEARN_SAMPLE]
        if heard:
            self.heard.append(m)
            self.heard_size += len(m)
            while self.heard_size > LEARN_HEARD:
                self.heard_size -= len(self.heard.popleft())
        else:
            self.own.append(m)
            self.own_size += len(m)
            while self.own_size > LEARN_MAX:
                self.own_size -= len(self.own.popleft())

    def save(self, m: bytes, heard: bool):
        """Queues a message for the file; when the file has outgrown the history twice, it is
        written anew from the history."""
        self.buf += _record(m, heard)
        if self.file_size + len(self.buf) > 2 * (LEARN_MAX + LEARN_HEARD):
            self.rewrite = True

    def flush(self):
        """Writes the queued records (once a batch, off the sending path)."""
        if self.gone or not (self.buf or self.rewrite):
            return
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            if self.rewrite:
                data = b"".join(_record(x, False) for x in self.own) + b"".join(_record(x, True) for x in self.heard)
                write_atomic(self.path, data)
                self.file_size = len(data)
            else:
                with open(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "ab") as f:
                    f.write(self.buf)
                self.file_size += len(self.buf)
        except OSError:
            pass
        self.buf, self.rewrite = bytearray(), False

    def samples(self) -> tuple[list[bytes], list[bytes]]:
        """Our messages and the newest received ones that fill the history (copies for training)."""
        heard = list(self.heard)
        return list(self.own), heard[len(heard) - _count_from(heard, max(0, LEARN_HEARD - self.own_size)):]


def _count_from(msgs: list[bytes], n: int) -> int:
    """How many of the newest messages fit in n bytes."""
    c = 0
    for m in reversed(msgs):
        if n < len(m):
            break
        n -= len(m)
        c += 1
    return c


def train(own: list[bytes], heard: list[bytes], size: int) -> Dict:
    """Trains a dictionary of up to size bytes (runs in a worker thread). zstd's fastCover, the
    algorithm of `zstd --train`, tries several segment and d-mer sizes on the training samples
    and keeps the one that compresses the held-out ones best; tested on our newest messages:
    the dictionary is for what we send."""
    if len(own) >= 8:
        split = len(own) * 3 // 4
        samples = heard + own
        n_train = len(heard) + split
    else:
        samples = heard + own
        n_train = len(samples) * 3 // 4
    if n_train < 4 or len(samples) - n_train < 2:
        raise ValueError("too few samples")
    zid = random.randrange(1 << 15, (1 << 31) - 1)  # not a reserved id
    zd = zstandard.train_dictionary(size, samples, split_point=n_train / len(samples), dict_id=zid,
                                    steps=40, threads=1)
    return Dict(zd.as_bytes())
