"""Via a third device (spec §3): a device both trust carries a pair's packets inside its own
sessions with each of them — event 0.7 forward [to, packet] to it, event 0.8 forwarded
[from, packet] from it. The packets stay end-to-end encrypted: the forwarder sees what a relay
sees. It forwards only for pairs its person opted it in for (allow_forward), one hop only,
within a rate limit, and never ahead of its own traffic. Mixed into Node."""
import base64
import time

from .cbor import decode, encode
from .delivery import MAX_PACKET

EV_FORWARD = 7  # event 0.7 forward [to, packet]: to a forwarder
EV_FORWARDED = 8  # event 0.8 forwarded [from, packet]: from a forwarder

# how many bytes a second a forwarder carries in one direction of a pair, unless
# Node.forward_rate says otherwise
DEFAULT_FORWARD_RATE = 256 << 10
FORWARD_BURST = 64 << 10  # bytes a direction may send at once above its rate
# past this many parts waiting to go to a device, packets to forward to it (and our own packets
# for a forwarder) are dropped — our own traffic goes first
FORWARD_QUEUE = 128
MAX_ROAD_PACKET = MAX_PACKET + 64


def addr_bytes(addr: str) -> bytes | None:
    """An address as it goes on the wire: 16 bytes; None — not an address."""
    try:
        b = base64.b32decode(addr.upper() + "=" * (-len(addr) % 8))
    except Exception:
        return None
    return b if len(b) == 16 else None


def addr_text(b: bytes) -> str:
    """An address from the wire."""
    return base64.b32encode(b).decode().rstrip("=").lower()


def forward_stream(addr: bytes) -> int:
    """The stream forward events about a device go on: its address's first 8 bytes, so a loss
    towards one device holds up nothing else."""
    return int.from_bytes(addr[:8], "big") or 1


def forward_msg(m: bytes) -> bool:
    """Events 0.7 and 0.8: never compressed, run out of order (spec §3)."""
    return len(m) > 3 and m[1] == 3 and m[2] == 0 and m[3] in (EV_FORWARD, EV_FORWARDED)


class ViaRoad:
    """The road to other devices through forwarder x: send wraps a packet into event 0.7 to x;
    what x hands over (0.8) arrives on it. The endpoint's address is the device at the other end."""

    def __init__(self, node, x: str):
        self.node, self.x = node, x
        self.name = "via:" + x

    def send(self, to: str, pkt: bytes):
        n = self.node
        raw = addr_bytes(to)
        if len(pkt) > MAX_ROAD_PACKET or raw is None:
            return
        ps = n.peers.get(self.x)
        if ps is None or not n._direct(ps, time.time()) or len(ps.st.queue) >= FORWARD_QUEUE:
            return
        ps.st.push(encode([3, 0, EV_FORWARD, raw, pkt]), False, forward_stream(raw), False)
        n._wake()

    def close(self):
        pass


def is_via(road) -> bool:
    return isinstance(road, ViaRoad)


class _Pending:
    __slots__ = ("to", "msg", "stream", "size")

    def __init__(self, to: str, msg: bytes, stream: int, size: int):
        self.to, self.msg, self.stream, self.size = to, msg, stream, size


class _Bucket:
    """Shapes one forwarded direction: a token bucket of the forward rate with bursts of
    FORWARD_BURST bytes. What comes over the rate waits, up to FORWARD_BURST bytes, and goes as
    the bucket refills — the queue it builds tells the pair's congestion control to slow down;
    past that it is dropped."""
    __slots__ = ("tokens", "at", "q", "queued")

    def __init__(self, now: float):
        self.tokens, self.at, self.q, self.queued = float(FORWARD_BURST), now, [], 0


class Forwarding:
    """The forwarding half of Node (spec §3)."""

    def _forward_init(self):
        # how many bytes a second we forward in one direction of a pair we forward for
        # (allow_forward); 0 — DEFAULT_FORWARD_RATE
        self.forward_rate = 0
        self._vias: dict[str, ViaRoad] = {}  # roads through forwarders, by forwarder
        self._fwd_buckets: dict[str, _Bucket] = {}  # rate limit per forwarded direction ("from>to")
        self._forward_tap = None  # tests: what we forward, (from, to, pkt)
        self._fwd_count = 0
        self._fwd_dropped = 0

    def _via(self, x: str) -> ViaRoad:
        """The road through forwarder x."""
        v = self._vias.get(x)
        if v is None:
            v = self._vias[x] = ViaRoad(self, x)
        return v

    def allow_forward(self, a: str, b: str, on: bool):
        """Opts this device in (on) or out as a forwarder between two devices it trusts (spec §3):
        one consent for both directions, kept with the trusted list. Both devices learn it from
        our hello, sent again to them at once."""
        from .node import ERR_FAILED, KIND_PLUGIN, P2PACTError
        if a == b or self.id.addr in (a, b):
            raise P2PACTError(ERR_FAILED, "forwarding needs two other devices")
        pa, pb = self.trust.get(a), self.trust.get(b)
        if pa is None or pb is None:
            raise P2PACTError(ERR_FAILED, "unknown device")
        if KIND_PLUGIN in (pa.kind, pb.kind):
            raise P2PACTError(ERR_FAILED, "a plugin is reachable over the local socket only")

        def set_(p, other) -> bool:
            lst = [s for s in p.forward if s != other]
            if on:
                lst = sorted(lst + [other])
            if lst == p.forward:
                return False
            self.trust.set_forward(p.addr, lst)
            return True
        if set_(pa, b):
            self._hello(a)
        if set_(pb, a):
            self._hello(b)

    def forwards(self, peer: str) -> list[str]:
        """The devices we forward to for a known device (allow_forward)."""
        p = self.trust.get(peer)
        if p is None:
            return []
        return [a for a in p.forward if a != peer and self.trust.get(a) is not None]

    def forwarders(self, peer: str) -> list[str]:
        """The devices that forward for us to peer: their hellos list it."""
        return sorted(x for x, xs in self.peers.items() if x != peer and peer in xs.forwards)

    def forward_stats(self) -> tuple[int, int]:
        """Packets this device forwarded for others, and those it dropped."""
        return self._fwd_count, self._fwd_dropped

    def _hello(self, peer: str):
        """Sends our hello again to a device in session (what we forward for it changed)."""
        if peer in self.current and self._peer(peer) is not None:
            self._send_info(peer)

    def _forwards_wire(self, peer: str) -> list[bytes]:
        """The hello's ninth element: what we forward to for peer; [] — none (left out)."""
        return [b for a in self.forwards(peer) if (b := addr_bytes(a)) is not None]

    def _heard_forwards(self, x: str, ps, lst):
        """Takes the list a device's hello gave: the devices it forwards to for us. A device
        newly reachable through it gets a handshake at once."""
        old = ps.forwards
        ps.forwards = []
        for b in lst if isinstance(lst, list) else []:
            if isinstance(b, bytes) and len(b) == 16:
                if (a := addr_text(b)) not in (x, self.id.addr):  # trust is checked on use
                    ps.forwards.append(a)
        now = time.time()
        for a in ps.forwards:
            if a in old or a in self.current:
                continue
            if (pa := self._peer(a)) is not None:
                pa.last_init = 0.0
                nxt = None if pa.st.idle() else pa.st.next_packet(now)
                self._start_init(now, a, pa, nxt[0] if nxt else None)

    def _forward(self, frm: str, args: list[bytes]):
        """Device frm asks us to carry a packet to another device (event 0.7). Anything we may
        not or cannot forward is dropped silently."""
        to, pkt = _two_bytes(args)
        if to is None or len(to) != 16 or len(pkt) < 5 or len(pkt) > MAX_ROAD_PACKET:
            self._fwd_dropped += 1
            return
        now = time.time()
        dest = addr_text(to)
        pf = self.trust.get(frm)
        if dest in (frm, self.id.addr) or pf is None or self.trust.get(dest) is None or dest not in pf.forward:
            self._fwd_dropped += 1
            return
        pd, ps = self._peer(dest), self.peers.get(frm)
        if (ps is None or pd is None or not self._direct(ps, now) or not self._direct(pd, now)
                or len(pd.st.queue) >= FORWARD_QUEUE):
            self._fwd_dropped += 1
            return
        src = addr_bytes(frm)
        msg = encode([3, 0, EV_FORWARDED, src, pkt])
        if not self._fwd_offer(frm + ">" + dest, _Pending(dest, msg, forward_stream(src), len(pkt)), time.monotonic()):
            self._fwd_dropped += 1
            return
        if tap := self._forward_tap:
            tap(frm, dest, pkt)

    def _fwd_refill(self, b: _Bucket, now: float):
        rate = float(self.forward_rate) if self.forward_rate > 0 else float(DEFAULT_FORWARD_RATE)
        if now <= b.at:
            return
        b.tokens = min(float(FORWARD_BURST), b.tokens + rate * (now - b.at))
        b.at = now

    def _fwd_offer(self, dir_: str, p: _Pending, now: float) -> bool:
        """Forwards p now, or queues it behind its direction's rate; False — dropped."""
        b = self._fwd_buckets.get(dir_)
        if b is None:
            b = self._fwd_buckets[dir_] = _Bucket(now)
        self._fwd_refill(b, now)
        if not b.q and b.tokens >= p.size:
            b.tokens -= p.size
            self._fwd_send(p)
            return True
        if b.queued + p.size > FORWARD_BURST:
            return False
        b.q.append(p)
        b.queued += p.size
        return True

    def _fwd_release(self, now: float):
        """Forwards what waited for its direction's rate (called with every pump)."""
        for dir_, b in list(self._fwd_buckets.items()):
            if not b.q:
                if now - b.at > 60:
                    del self._fwd_buckets[dir_]  # full again long ago
                continue
            self._fwd_refill(b, now)
            while b.q and b.tokens >= b.q[0].size:
                p = b.q.pop(0)
                b.queued -= p.size
                b.tokens -= p.size
                self._fwd_send(p)

    def _fwd_send(self, p: _Pending):
        pd = self.peers.get(p.to)
        if pd is None:
            return
        pd.st.push(p.msg, False, p.stream, False)
        self._fwd_count += 1
        self._wake()

    def _forwarded(self, x: str, args: list[bytes]):
        """Forwarder x hands over a packet another device sent us through it (event 0.8). It is
        handled as arriving on the road via x — only from a device x told us it forwards to, and
        only over a road to x that is not via a third device."""
        src, pkt = _two_bytes(args)
        if src is None or len(src) != 16 or len(pkt) < 5 or len(pkt) > MAX_ROAD_PACKET:
            return
        frm = addr_text(src)
        xs = self.peers.get(x)
        if (frm in (x, self.id.addr) or xs is None or frm not in xs.forwards or self.trust.get(frm) is None
                or not self._direct(xs, time.time())):
            return
        self._receive(pkt, (self._via(x), frm))


def _two_bytes(args: list[bytes]) -> tuple[bytes | None, bytes]:
    if len(args) < 2:
        return None, b""
    try:
        a, b = decode(args[0]), decode(args[1])
    except Exception:
        return None, b""
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        return None, b""
    return a, b
