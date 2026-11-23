"""The window of parts held above the first gap (GOT_MAX)."""
from p2pact.delivery import GOT_MAX, Stream


def test_gap_past_got_max():
    """A lost part with more than GOT_MAX parts sent after it: the receiver must still take the
    part its gap waits for, and the sender must not run GOT_MAX past it. Before, the receiver
    bounded the number of parts held above the gap: once GOT_MAX arrived it dropped the missing
    part's every copy, and delivery stopped for good while the session stayed alive."""
    a, b = Stream(), Stream()
    a.reliable = True
    n = GOT_MAX + 2000
    for i in range(n):
        a.push(b"m%d" % i, False)
    got = []
    now = 1000.0
    dropped = False
    for step in range(20000):
        if len(got) >= n:
            break
        now += 0.005
        for _ in range(256):
            p, retry = a.next_packet(now) or (None, False)
            if p is None:
                break
            # the first copy of part 1 and every retransmission in the first second are lost
            # (here, unlike in Go, the sender also retransmits a gap early on the acks' ranges)
            if not dropped or (retry and step < 200):
                dropped = True
                continue
            b.receive(now, p, lambda m, *x: got.append(m))
            assert len(b.got) <= GOT_MAX + 1, f"receiver holds {len(b.got)} parts"
        ack = b.next_packet(now, True)
        if ack is not None and len(ack[0]) > 1:
            a.receive(now, ack[0], None)
    assert len(got) == n, (
        f"delivered {len(got)} of {n}: recv_ack={b.recv_ack} got={len(b.got)} "
        f"inflight={len(a.inflight)} queue={len(a.queue)}")
    assert got == [b"m%d" % i for i in range(n)]


def test_receive_window():
    """The receiver alone (an old sender runs ahead): the part at recv_ack is taken even with
    GOT_MAX-1 parts held above it, and a part GOT_MAX past it is dropped."""
    a, b = Stream(), Stream()
    a.reliable = True
    for i in range(GOT_MAX + 1):
        a.push(bytes([i & 255]), False)
    pkts = []
    while len(pkts) < GOT_MAX + 1:
        r = a.next_packet(1000.0)
        if r is None:  # the window: let everything sent so far count as acked
            a.inflight.clear()
            a.inflight_bytes = 0
            continue
        pkts.append(r[0])
    n = []
    for p in pkts[1:]:
        b.receive(1000.0, p, lambda *x: n.append(1))
    assert len(b.got) == GOT_MAX - 1 and b.recv_ack == 1
    b.receive(1000.0, pkts[0], lambda *x: n.append(1))
    assert b.recv_ack == GOT_MAX + 1 and len(n) == GOT_MAX
