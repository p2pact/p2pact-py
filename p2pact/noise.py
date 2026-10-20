"""The Noise Protocol Framework, just what P2PACT uses: Noise_IK and Noise_XXpsk2 with
25519, ChaChaPoly and BLAKE2s."""
from .crypto import blake2s, hmac, open_, seal, x25519, x25519_keypair

SUITE = "25519_ChaChaPoly_BLAKE2s"


class CipherState:
    def __init__(self, k: bytes | None = None):
        self.k, self.n = k, 0

    def encrypt(self, ad: bytes, pt: bytes) -> bytes:
        if self.k is None:
            return pt
        ct = seal(self.k, self.n, ad, pt)
        self.n += 1
        return ct

    def decrypt(self, ad: bytes, ct: bytes) -> bytes:
        if self.k is None:
            return ct
        pt = open_(self.k, self.n, ad, ct)
        if pt is None:
            raise ValueError("noise: decryption failed")
        self.n += 1
        return pt

    def encrypt_at(self, n: int, ad: bytes, pt: bytes) -> bytes:
        return seal(self.k, n, ad, pt)

    def decrypt_at(self, n: int, ad: bytes, ct: bytes) -> bytes | None:
        return open_(self.k, n, ad, ct)


def _hkdf(ck: bytes, ikm: bytes, n: int) -> list[bytes]:
    t = hmac(ck, ikm)
    o1 = hmac(t, b"\x01")
    o2 = hmac(t, o1, b"\x02")
    return [o1, o2] if n == 2 else [o1, o2, hmac(t, o2, b"\x03")]


class _Symmetric:
    def __init__(self, name: str):
        b = name.encode()
        self.h = b.ljust(32, b"\x00") if len(b) <= 32 else blake2s(b)
        self.ck = self.h
        self.cs = CipherState()

    def mix_key(self, ikm: bytes):
        self.ck, k = _hkdf(self.ck, ikm, 2)
        self.cs = CipherState(k)

    def mix_hash(self, data: bytes):
        self.h = blake2s(self.h, data)

    def mix_key_and_hash(self, ikm: bytes):
        self.ck, th, k = _hkdf(self.ck, ikm, 3)
        self.mix_hash(th)
        self.cs = CipherState(k)

    def encrypt_and_hash(self, pt: bytes) -> bytes:
        ct = self.cs.encrypt(self.h, pt)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct: bytes) -> bytes:
        pt = self.cs.decrypt(self.h, ct)
        self.mix_hash(ct)
        return pt

    def split(self):
        a, b = _hkdf(self.ck, b"", 2)
        return CipherState(a), CipherState(b)


PATTERNS = {
    "IK": ("rs", [["e", "es", "s", "ss"], ["e", "ee", "se"]]),
    "XXpsk2": (None, [["e"], ["e", "ee", "s", "es", "psk"], ["s", "se"]]),
}


class Handshake:
    """One Noise handshake; after the last message `ciphers` holds (c1, c2)."""

    def __init__(self, pattern: str, initiator: bool, prologue: bytes, s: tuple[bytes, bytes],
                 rs: bytes | None = None, psk: bytes | None = None):
        pre, self.msgs = PATTERNS[pattern]
        self.initiator, self.s, self.rs, self.psk = initiator, s, rs, psk
        self.psk_mode = "psk" in pattern
        self.ss = _Symmetric(f"Noise_{pattern}_{SUITE}")
        self.ss.mix_hash(prologue)
        if pre == "rs":
            self.ss.mix_hash(rs if initiator else s[1])
        self.e = None
        self.re = None
        self.i = 0
        self.ciphers = None

    def _dh(self, priv: bytes, pub: bytes):
        self.ss.mix_key(x25519(priv, pub))

    def _token(self, t: str, write: bool, out: list, inp: list):
        init = self.initiator
        if t == "e":
            if write:
                self.e = x25519_keypair()
                out.append(self.e[1])
                self.ss.mix_hash(self.e[1])
                if self.psk_mode:
                    self.ss.mix_key(self.e[1])
            else:
                b, pos = inp
                if len(b) < pos + 32:
                    raise ValueError("noise: short message")
                self.re = b[pos:pos + 32]
                inp[1] = pos + 32
                self.ss.mix_hash(self.re)
                if self.psk_mode:
                    self.ss.mix_key(self.re)
        elif t == "s":
            if write:
                out.append(self.ss.encrypt_and_hash(self.s[1]))
            else:
                b, pos = inp
                n = 32 + (16 if self.ss.cs.k else 0)
                if len(b) < pos + n:
                    raise ValueError("noise: short message")
                self.rs = self.ss.decrypt_and_hash(b[pos:pos + n])
                inp[1] = pos + n
        elif t == "ee":
            self._dh(self.e[0], self.re)
        elif t == "es":
            self._dh(self.e[0], self.rs) if init else self._dh(self.s[0], self.re)
        elif t == "se":
            self._dh(self.s[0], self.re) if init else self._dh(self.e[0], self.rs)
        elif t == "ss":
            self._dh(self.s[0], self.rs)
        elif t == "psk":
            self.ss.mix_key_and_hash(self.psk)

    def _finish(self):
        self.i += 1
        if self.i == len(self.msgs):
            self.ciphers = self.ss.split()

    def write_message(self, payload: bytes = b"") -> bytes:
        out: list = []
        for t in self.msgs[self.i]:
            self._token(t, True, out, [b"", 0])
        out.append(self.ss.encrypt_and_hash(payload))
        self._finish()
        return b"".join(out)

    def read_message(self, msg: bytes) -> bytes:
        inp = [bytes(msg), 0]
        for t in self.msgs[self.i]:
            self._token(t, False, [], inp)
        payload = self.ss.decrypt_and_hash(inp[0][inp[1]:])
        self._finish()
        return payload
