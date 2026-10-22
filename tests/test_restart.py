"""Restarts (spec §4.2), acks of timer copies (§5) and ordered dispatch (§6)."""
import asyncio
import random

from p2pact.cbor import decode
from p2pact.delivery import Stream
from p2pact.node import Node

from test_node import echo, make, pair


def test_spurious_retransmission():
    """A timeout fired by a queue, not a loss: the ack of the first copy comes just after the
    retransmission; it must not mark the parts sent between the copies lost, and it is a
    round-trip sample."""
    a, b = Stream(), Stream()
    t0 = 1000.0

    def exchange(at, *pkts):
        for p in pkts:
            b.receive(at, p, lambda *x: None)
        ack, _ = b.next_packet(at, True)
        a.receive(at + 0.001, ack, None)

    a.push(b"first", False, 1)  # a round-trip sample: 60 ms
    p, _ = a.next_packet(t0)
    exchange(t0 + 0.059, p)
    sent = t0 + 0.1
    pkts = []
    for _ in range(5):
        a.push(b"queued", False, 1)
        pkts.append(a.next_packet(sent)[0])
    at = sent + a._timeout(a.inflight[2], 0)
    _, retry = a.next_packet(at)
    assert retry, "no retransmission on timeout"
    srtt = a.srtt
    exchange(at + 0.001, pkts[0])  # the first copy, late behind a queue
    assert 2 not in a.inflight
    for seq, p in a.inflight.items():
        assert p.sent, f"part {seq} taken as lost"
    assert a.srtt > srtt, "the ack of the earlier copy is no round-trip sample"


def test_reset_drops_replies():
    """The other device restarted: our unacknowledged calls go again, renumbered; replies to
    its old calls are dropped; the path is measured afresh."""
    a = Stream()
    a.push(b"call", False, 1)
    a.push(b"reply", False, 2, reply=True)
    a.push(b"queued reply", False, 2, reply=True)
    a.next_packet(1000.0)
    a.next_packet(1000.0)
    a.srtt, a.min_rtt, a.bw, a.cwnd = 0.3, 0.1, 5000.0, 100.0
    a.reset()
    assert [p.data for p in a.queue] == [b"call"]
    assert a.queue[0].seq == 1 and a.queue[0].num == 1 and a.next == 2
    assert a.srtt == a.min_rtt == a.bw == 0 and a.cwnd == 32


def test_order_of_events(tmp_path):
    """Events and calls of one stream run in the order sent, one at a time; a slow handler
    holds up its own stream only."""
    async def run():
        a, b = await make(tmp_path, "laptop"), await make(tmp_path, "phone")
        try:
            await pair(a, b)
            release = asyncio.Event()

            async def slow(peer, args):
                await release.wait()
                return []
            b.handle(64, 2, slow)
            got, total = [], 300
            done = asyncio.Event()

            async def on_event(peer, tool, ev, args):
                await asyncio.sleep(random.random() * 0.0002)  # a task per event would reorder
                got.append(ev)
                if len(got) == total:
                    done.set()
            b.on_event = on_event
            call = asyncio.create_task(a.call_on(b.id.addr, 2, 64, 2))
            await asyncio.sleep(0.05)
            a.event_on(b.id.addr, 2, 64, 0)  # behind the slow call
            for i in range(1, total):
                a.event_on(b.id.addr, 1, 64, i)
            try:
                await asyncio.wait_for(done.wait(), 3)
                raise AssertionError("an event overtook the slow call on its stream")
            except asyncio.TimeoutError:
                pass
            assert len(got) == total - 1, f"the slow call held up another stream: {len(got)}"
            release.set()
            await asyncio.wait_for(done.wait(), 10)
            await asyncio.wait_for(call, 10)
            assert got[-1] == 0
            assert got[:-1] == list(range(1, total))
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_restart_with_parts_in_flight(tmp_path):
    """The other device restarts silently while our calls are in flight: we handshake again
    with a part in the first packet, numbered for its old boot; its reply renumbers everything
    (spec §4.2). Every call must still run exactly once, and later calls must not be lost."""
    async def run():
        a, b = await make(tmp_path, "laptop"), await make(tmp_path, "phone")
        b2 = None
        try:
            await pair(a, b)
            for _ in range(10):  # the numbering moves on
                await echo(a, b, b"before")
            baddr = b.udp.local_addr()
            b.udp.drop = lambda: True  # the calls below never reach the old boot
            runs: dict[str, int] = {}

            def count(peer, args):
                s = decode(args[0])
                runs[s] = runs.get(s, 0) + 1
                return [s]

            async def call(s):
                res = await asyncio.wait_for(a.call(b.id.addr, 64, 3, s), 10)
                assert decode(res[0]) == s, f"{s!r} answered {decode(res[0])!r}"

            lost = [asyncio.create_task(call(f"lost {i}")) for i in (1, 2, 3)]
            await asyncio.sleep(0.3)
            b.close()
            await asyncio.sleep(0.05)  # the socket closes on the next loop turn
            b2 = Node(str(tmp_path / "phone"), "phone")
            b2.handle(64, 3, count)
            await b2.listen_udp(baddr)
            # we notice first: the session is gone and the lost calls are due, so the first one
            # rides in the handshake's first packet
            a.current.pop(b.id.addr, None)
            for p in a.peers[b.id.addr].st.inflight.values():
                p.sent = 0.0
            a._wake()
            await asyncio.sleep(0.3)
            b2.start()
            await asyncio.gather(*lost)
            for i in range(20):
                await call(f"after {i}")
            assert {s: n for s, n in runs.items() if n != 1} == {}
            assert len(runs) == 23
        finally:
            a.close()
            b.close()
            if b2:
                b2.close()
    asyncio.run(run())
