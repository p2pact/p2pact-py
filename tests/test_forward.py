"""Via a third device (spec §3): forwarding through a device both trust (as p2pact-go's
forward_test.go)."""
import asyncio
import os
import time

import pytest

from p2pact import node as node_mod
from p2pact.cbor import decode
from p2pact.forward import EV_FORWARD, FORWARD_BURST, _Pending, addr_bytes, addr_text
from p2pact.node import P_INIT, Node, _PeerState
from p2pact.store import Invite, Peer, Trust


async def make(tmp_path, name, udp=True):
    n = Node(str(tmp_path / name), name)
    if udp:
        await n.listen_udp("127.0.0.1:0")
    n.handle(64, 1, lambda peer, args: [decode(args[0])])
    n.start()
    return n


async def pair(owner, joiner):
    await joiner.join(Invite.parse(str(owner.invite(60))), 10)
    await eventually("the owner knows the joiner", lambda: owner.trust.get(joiner.id.addr) is not None)


def friends(p, q):
    p.befriend(Peer(q.id.addr, q.id.key[1], q.name, b""))
    q.befriend(Peer(p.id.addr, p.id.key[1], p.name, b""))


async def echo(frm, to, data: bytes, timeout=10.0):
    res = await asyncio.wait_for(frm.call(to.id.addr, 64, 1, data), timeout)
    assert decode(res[0]) == data


async def eventually(what, cond, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = cond()
        if asyncio.iscoroutine(r):
            r = await r
        if r:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("never: " + what)


async def unreachable(frm, to, data: bytes):
    """frm's call to `to` does not get through within 2 s."""
    with pytest.raises(Exception):
        await asyncio.wait_for(frm.call(to.id.addr, 64, 1, data), 2)


async def three_nodes(tmp_path):
    """A and B trust each other but cannot reach each other — they know no address of the other
    and announce none — while both are paired with X over UDP."""
    a, x, b = await make(tmp_path, "A"), await make(tmp_path, "X"), await make(tmp_path, "B")
    a.set_advertise({})
    b.set_advertise({})
    await pair(x, a)
    await pair(x, b)
    friends(a, b)
    return a, x, b


class Tap:
    """Records what X forwards."""

    def __init__(self, x: Node):
        self.pkts: list[bytes] = []
        x._forward_tap = lambda frm, to, pkt: self.pkts.append(bytes(pkt))

    def contains(self, b: bytes) -> tuple[int, bool]:
        return len(self.pkts), any(b in p for p in self.pkts)


def close(*nodes):
    for n in nodes:
        n.close()


async def test_forward_via_third_device(tmp_path):
    """A and B, which cannot reach each other, set up a session through X and talk both ways —
    calls, events, a long message; X carries only ciphertext."""
    a, x, b = await three_nodes(tmp_path)
    try:
        tap = Tap(x)
        x.allow_forward(a.id.addr, b.id.addr, True)
        assert x.forwards(a.id.addr) == [b.id.addr]
        await eventually("A hears X forwards to B", lambda: a.forwarders(b.id.addr) == [x.id.addr])

        marker = b"plaintext-marker-that-X-must-never-see"
        msg = b"." * 100 + marker
        await echo(a, b, msg)
        await echo(b, a, msg)
        via = "via:" + x.id.addr
        assert a.paths(b.id.addr) == [via]
        assert b.paths(a.id.addr) == [via]

        long = os.urandom(40 << 10)
        await echo(a, b, long, 20)
        await echo(b, a, long, 20)

        got: asyncio.Queue = asyncio.Queue()
        for n in (a, b):
            n.on_event = lambda peer, tool, ev, args: got.put_nowait(decode(args[0]))
        a.event(b.id.addr, 64, 3, "to B")
        b.event(a.id.addr, 64, 3, "to A")
        seen = {await asyncio.wait_for(got.get(), 5) for _ in range(2)}
        assert seen == {"to A", "to B"}

        n, found = tap.contains(marker)
        assert n > 0, "X forwarded nothing"
        assert not found, "X saw the plaintext"
        assert x.forward_stats()[0] > 0
        # the consent is kept with the trusted list
        p = Trust(x.dir).get(a.id.addr)
        assert p is not None and p.forward == [b.id.addr]
    finally:
        close(a, x, b)


def forge(a, x, b):
    """Sends X an event 0.7 for B by hand."""
    a.event(x.id.addr, 0, EV_FORWARD, addr_bytes(b.id.addr), bytes((P_INIT,)) + os.urandom(200))


async def test_forward_refused(tmp_path):
    """X forwards nothing for a pair it was not opted in for, nor to a device it does not trust,
    and stops when it forgets one of the two."""
    a, x, b = await three_nodes(tmp_path)
    stranger = await make(tmp_path, "S", udp=False)
    try:
        tap = Tap(x)
        # not opted in: no road via X, and a forged 0.7 is dropped
        await unreachable(a, b, b"hi")
        forge(a, x, b)
        await eventually("X drops the forged packet", lambda: x.forward_stats()[1] > 0)
        assert tap.contains(b"")[0] == 0, "X forwarded without consent"

        # only between devices X trusts, never to itself
        with pytest.raises(Exception):
            x.allow_forward(a.id.addr, stranger.id.addr, True)
        with pytest.raises(Exception):
            x.allow_forward(a.id.addr, x.id.addr, True)

        # opted in, then X forgets B: A learns it, and X forwards nothing more
        x.allow_forward(a.id.addr, b.id.addr, True)
        await echo(a, b, b"through X")
        x.forget(b.id.addr)
        await eventually("A hears X no longer forwards to B", lambda: not a.forwarders(b.id.addr))
        before = tap.contains(b"")[0]
        dropped = x.forward_stats()[1]
        forge(a, x, b)
        await eventually("X drops a packet for a device it forgot", lambda: x.forward_stats()[1] > dropped)
        assert tap.contains(b"")[0] == before, "X forwarded to a device it forgot"
    finally:
        close(a, x, b, stranger)


async def test_forward_withdrawn(tmp_path):
    """Withdrawing the consent stops forwarding and tells both devices."""
    a, x, b = await three_nodes(tmp_path)
    try:
        x.allow_forward(a.id.addr, b.id.addr, True)
        await echo(a, b, b"through X")
        x.allow_forward(b.id.addr, a.id.addr, False)
        await eventually("both hear X no longer forwards",
                         lambda: not a.forwarders(b.id.addr) and not b.forwarders(a.id.addr))
        dropped = x.forward_stats()[1]
        forge(a, x, b)
        await eventually("X drops the packet", lambda: x.forward_stats()[1] > dropped)
    finally:
        close(a, x, b)


def test_forward_bucket(tmp_path):
    """The rate limit: a direction may send a burst, then only its rate; what is over the rate
    waits, up to a burst, and goes as the bucket refills; past that it is dropped."""
    n = Node(str(tmp_path / "n"), "n")
    n.forward_rate = 1000
    n._wake = lambda: None
    n.peers = {"a": _PeerState("a"), "b": _PeerState("b")}
    now = time.monotonic()
    p = lambda to: _Pending(to, b"\x01", 1, 1000)
    offered = 0
    while n._fwd_offer("a>b", p("b"), now):
        offered += 1
    burst = FORWARD_BURST // 1000
    assert n.forward_stats()[0] == burst and offered == 2 * burst
    n._fwd_release(now + 0.4)  # 536 left + 400: not enough
    assert n.forward_stats()[0] == burst, "more than the rate"
    n._fwd_release(now + 2.1)
    assert n.forward_stats()[0] == burst + 2, "the rate refills"
    assert n._fwd_offer("b>a", p("a"), now) and n.forward_stats()[0] == burst + 3, \
        "the other direction has its own bucket"


def test_addr_bytes(tmp_path):
    n = Node(str(tmp_path / "a"), "A")
    b = addr_bytes(n.id.addr)
    assert b is not None and len(b) == 16 and addr_text(b) == n.id.addr
    assert addr_bytes("nonsense") is None


async def test_forward_one_hop(tmp_path):
    """One hop only: X reaches B only through Y, so it does not forward A's packets to B (no
    chains)."""
    a, x, y, b = (await make(tmp_path, "A"), await make(tmp_path, "X"), await make(tmp_path, "Y"),
                  await make(tmp_path, "B"))
    try:
        a.set_advertise({})
        b.set_advertise({})
        await pair(y, x)
        await pair(y, b)
        await pair(x, a)
        x.set_advertise({})  # Y and A know where X is; B never learns it
        friends(x, b)
        friends(a, b)
        y.allow_forward(x.id.addr, b.id.addr, True)
        await echo(x, b, b"X to B through Y")
        x.allow_forward(a.id.addr, b.id.addr, True)
        await eventually("A hears X forwards to B", lambda: len(a.forwarders(b.id.addr)) == 1)
        await unreachable(a, b, b"two hops")
        fw, d = x.forward_stats()
        assert fw == 0 and d > 0, f"X forwarded {fw}, dropped {d}"
    finally:
        close(a, x, y, b)


async def test_forward_gives_way_to_direct(tmp_path, monkeypatch):
    """A road via a third device gives way to a direct one as soon as it answers (spec §7)."""
    monkeypatch.setattr(node_mod, "PROBE_EVERY", 0.3)
    a, x, b = await three_nodes(tmp_path)
    try:
        x.allow_forward(a.id.addr, b.id.addr, True)
        await echo(a, b, b"through X")
        a.set_advertise(None)  # A announces its UDP address again: B probes it

        async def moved():
            await echo(b, a, b"ping", 5)
            return "udp" in b.paths(a.id.addr)
        await eventually("the session moves to UDP", moved, 20)
        fw = x.forward_stats()[0]
        for _ in range(20):
            await echo(a, b, b"direct", 5)
        assert x.forward_stats()[0] - fw <= 4, "X still carried packets after UDP came up"
    finally:
        close(a, x, b)
