"""Device identity, known devices and invites (spec §1, §2). Same files as the Go
implementation: dir/net-key.json and dir/net-peers.json."""
import base64
import json
import os
import time
from dataclasses import dataclass, field

from .cbor import decode, encode
from .crypto import address, ed25519_public, mac, random_bytes, x25519, x25519_keypair

PROLOGUE = b"p2pact/1"
INVITE_PREFIX = "p2pact1."


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s) if s else b""


class Identity:
    def __init__(self, key: tuple[bytes, bytes], sign_seed: bytes):
        self.key = key  # (private, public)
        self.sign_seed = sign_seed
        self.sign_public = ed25519_public(sign_seed)

    @property
    def addr(self) -> str:
        return address(self.key[1])

    def shared(self, pub: bytes, label: str) -> bytes:
        return mac(x25519(self.key[0], pub), label)

    @staticmethod
    def load(dir_: str) -> "Identity":
        path = os.path.join(dir_, "net-key.json")
        try:
            f = json.load(open(path))
        except (OSError, ValueError):
            f = {}
        changed = False
        if not f.get("private"):
            priv, pub = x25519_keypair()
            f["private"], f["public"] = _b64(priv), _b64(pub)
            changed = True
        if not f.get("sign"):
            f["sign"] = _b64(random_bytes(32))
            changed = True
        if changed:
            os.makedirs(dir_, mode=0o700, exist_ok=True)
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as out:
                json.dump(f, out)
        return Identity(x25519_keypair(_unb64(f["private"])), _unb64(f["sign"]))


@dataclass
class Peer:
    addr: str
    key: bytes
    name: str
    pair_secret: bytes
    hints: dict = field(default_factory=dict)  # {"udp": [...], "tcp": [...], "relay": {"addr", "fp"}}
    added: int = 0
    sign_key: bytes | None = None
    os: str | None = None
    via: str | None = None


def phone(os_: str | None) -> bool:
    return os_ in ("android", "ios")


def hints_to_wire(h: dict):
    r = h.get("relay")
    return [h.get("udp"), [r["addr"], r["fp"]] if r else None, h.get("tcp")]


def hints_from_wire(v) -> dict:
    a = v if isinstance(v, list) else []
    strs = lambda x: [s for s in x if isinstance(s, str)] if isinstance(x, list) else []
    h = {}
    if udp := strs(a[0] if len(a) > 0 else None):
        h["udp"] = udp
    r = strs(a[1] if len(a) > 1 else None)
    if len(r) == 2 and r[0]:
        h["relay"] = {"addr": r[0], "fp": r[1]}
    if tcp := strs(a[2] if len(a) > 2 else None):
        h["tcp"] = tcp
    return h


class Trust:
    def __init__(self, dir_: str):
        self.path = os.path.join(dir_, "net-peers.json")
        self.peers: dict[str, Peer] = {}
        try:
            for j in json.load(open(self.path)):
                p = Peer(j["addr"], _unb64(j["key"]), j.get("name", ""), _unb64(j.get("pair_secret", "")),
                         j.get("hints") or {}, j.get("added", 0), _unb64(j["sign_key"]) if j.get("sign_key") else None,
                         j.get("os"), j.get("via"))
                if len(p.key) == 32 and address(p.key) == p.addr:
                    self.peers[p.addr] = p
        except (OSError, ValueError, KeyError):
            pass

    def get(self, addr: str) -> Peer | None:
        return self.peers.get(addr)

    def list(self) -> list[Peer]:
        return [self.peers[k] for k in sorted(self.peers)]

    def put(self, p: Peer):
        if not p.added:
            p.added = int(time.time() * 1000)
        self.peers[p.addr] = p
        self._save()

    def set_hints(self, addr: str, name: str, os_: str, h: dict):
        p = self.peers.get(addr)
        if not p:
            return
        if name:
            p.name = name
        if os_:
            p.os = os_
        for k in ("udp", "tcp", "relay"):
            if h.get(k):
                p.hints[k] = h[k]
        self._save()

    def remove(self, addr: str) -> bool:
        if self.peers.pop(addr, None) is None:
            return False
        self._save()
        return True

    def _save(self):
        out = []
        for p in self.list():
            j = {"addr": p.addr, "key": _b64(p.key), "name": p.name, "pair_secret": _b64(p.pair_secret),
                 "hints": p.hints, "added": p.added}
            if p.sign_key:
                j["sign_key"] = _b64(p.sign_key)
            if p.os:
                j["os"] = p.os
            if p.via:
                j["via"] = p.via
            out.append(j)
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        tmp = self.path + ".tmp"  # replaced in one step: never read half-written
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(out, f, indent=2)
        os.replace(tmp, self.path)


class Invite:
    def __init__(self, key: bytes, name: str, secret: bytes, exp: float, hints: dict):
        self.key, self.name, self.secret, self.exp, self.hints = key, name, secret, exp, hints

    @property
    def id(self) -> bytes:
        return mac(self.secret, "invite")[:16]

    def __str__(self) -> str:
        b = encode([1, self.key, self.name, self.secret, int(self.exp), hints_to_wire(self.hints)])
        return INVITE_PREFIX + base64.urlsafe_b64encode(b).decode().rstrip("=")

    @staticmethod
    def parse(s: str) -> "Invite":
        s = s.strip()
        if not s.startswith(INVITE_PREFIX):
            raise ValueError("not an invite")
        body = s[len(INVITE_PREFIX):]
        try:
            v = decode(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except Exception:
            raise ValueError("invite is corrupt")
        if (not isinstance(v, list) or len(v) < 6 or v[0] != 1 or not isinstance(v[1], bytes) or len(v[1]) != 32
                or not isinstance(v[3], bytes) or len(v[3]) != 32):
            raise ValueError("invite is corrupt")
        inv = Invite(v[1], str(v[2] or ""), v[3], float(v[4]), hints_from_wire(v[5]))
        if time.time() > inv.exp:
            raise ValueError("invite expired")
        return inv
