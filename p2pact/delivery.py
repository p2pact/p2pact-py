"""Delivery (spec §5): flags | [ack: varint up-to + varint bitmap] | [varint part number | part].
Messages go in packet-sized parts, acknowledged and retransmitted; congestion control as in
TCP NewReno with HyStart, timers per RFC 6298, a delivery-rate limit as in BBR."""

F_ACK, F_MSG, F_MORE, F_ZIP, F_ONCE, F_FIRST, F_CONT = 1, 2, 4, 8, 16, 32, 64
MAX_PACKET = 1200
DATA_HEADER = 9
ACK_BUDGET = 60
MAX_PART = MAX_PACKET - DATA_HEADER - 16 - 1 - ACK_BUDGET - 5 - 20
RTO_START, RTO_MIN, RTO_MAX = 0.5, 0.05, 4.0
ACK_DELAY = 0.04
CWND_START = CWND_MIN = 32
CWND_MAX = 4096
GOT_MAX = 8192
MSG_MAX = 16 << 20


def put_uvarint(out: bytearray, v: int) -> None:
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)


def read_uvarint(b: bytes, pos: int) -> tuple[int, int]:
    x = shift = 0
    for i in range(pos, min(len(b), pos + 10)):
        x |= (b[i] & 0x7F) << shift
        if b[i] < 0x80:
            return x, i + 1
        shift += 7
    raise ValueError("short varint")


class Part:
    __slots__ = ("seq", "data", "more", "zip", "first", "sent", "tries", "delivered", "stream", "num", "first_of_stream")

    def __init__(self, seq, data, more, zip_, stream=0, num=0, first_of_stream=False):
        self.seq, self.data, self.more, self.zip = seq, data, more, zip_
        self.stream, self.num, self.first_of_stream = stream, num, first_of_stream
        self.first = self.sent = 0.0
        self.tries = self.delivered = 0


class RPart:
    __slots__ = ("data", "more", "zip", "first", "streamed", "used", "stream", "num")

    def __init__(self, more, zip_):
        self.data, self.more, self.zip = b"", more, zip_
        self.first = self.streamed = self.used = False
        self.stream = self.num = 0


class Stream:
    def __init__(self):
        self.next = 1
        self.inflight: dict[int, Part] = {}
        self.queue: list[Part] = []
        self.cwnd, self.ssthresh = float(CWND_START), float(CWND_MAX)
        self.srtt = self.rttvar = self.min_rtt = self.last_cut = 0.0
        self.delivered, self.bw, self.bw_at = 0, 0.0, 0.0
        self.inflight_bytes, self.reliable = 0, False
        self._reset_recv()

    def _reset_recv(self):
        self.snext: dict[int, int] = {}
        self.recv_ack = 1
        self.got: dict[int, RPart] = {}
        self.next0 = 1
        self.asm0: list[bytes] = []
        self.asm0_len = 0
        self.zip0 = False
        self.streams: dict[int, list] = {}  # stream -> [next, {num: (msg, zip)}]
        self.ack_due = 0.0
        self.unacked = 0

    def rto(self) -> float:
        if self.srtt == 0:
            return RTO_START
        return min(max(self.srtt + 4 * self.rttvar, RTO_MIN), RTO_MAX)

    def _rate(self, now, r):
        if r >= self.bw or now - self.bw_at > 2:
            self.bw, self.bw_at = r, now

    def can_send(self) -> bool:
        """The congestion window, capped by twice the BDP in bytes while a queue builds;
        no window of our own on a reliable road (TCP controls congestion itself)."""
        if self.reliable:
            return len(self.inflight) < CWND_MAX
        if len(self.inflight) >= int(self.cwnd):
            return False
        queue = self.srtt > self.min_rtt + max(self.min_rtt / 2, 0.01)
        if queue and self.bw > 0 and self.min_rtt > 0:
            return self.inflight_bytes < 2 * self.bw * self.min_rtt + 4 * MAX_PART
        return True

    def _timeout(self, p: Part, ahead: int) -> float:
        t = self.rto()
        if self.bw > 0:
            t += ahead * MAX_PART / self.bw
        # back off only on congestion, or after three tries in a row: a random loss is no reason
        backoff = p.tries - 1 if self._queueing() else max(0, p.tries - 3)
        for _ in range(backoff):
            if t >= RTO_MAX:
                break
            t *= 2
        return min(t, RTO_MAX)

    def _queueing(self) -> bool:
        return self.srtt > self.min_rtt + max(self.min_rtt / 2, 0.01)

    def _sample(self, rtt):
        if self.min_rtt == 0 or rtt < self.min_rtt:
            self.min_rtt = rtt
        if self.cwnd < self.ssthresh and rtt > self.min_rtt + max(self.min_rtt / 2, 0.004):
            self.ssthresh = self.cwnd
        if self.srtt == 0:
            self.srtt, self.rttvar = rtt, rtt / 2
            return
        self.rttvar = (3 * self.rttvar + abs(self.srtt - rtt)) / 4
        self.srtt = (7 * self.srtt + rtt) / 8

    def _acked(self, n):
        queue = self._queueing()  # slow start, and while no queue builds (as BBR probes)
        for _ in range(n):
            self.cwnd += 1 if self.cwnd < self.ssthresh or not queue else 1 / self.cwnd
        self.cwnd = min(self.cwnd, CWND_MAX)

    def _lost(self, now):
        # only while a queue builds: a loss without one is random, not congestion
        if now - self.last_cut < max(self.srtt, RTO_MIN) or not self._queueing():
            return
        self.last_cut = now
        self.ssthresh = max(self.cwnd / 2, CWND_MIN)
        self.cwnd = self.ssthresh

    def reset(self):
        pending = sorted(self.inflight.values(), key=lambda p: p.seq) + self.queue
        self.next, self.inflight, self.queue, self.inflight_bytes = 1, {}, [], 0
        self._reset_recv()
        for p in pending:
            p.seq, p.first, p.sent, p.tries, p.delivered = self.next, 0.0, 0.0, 0, 0
            self.next += 1
            if p.first_of_stream:
                self.snext[p.stream] = self.snext.get(p.stream, 0) + 1
                p.num = self.snext[p.stream]
            self.queue.append(p)

    def push(self, msg: bytes, zip_: bool, stream: int = 0):
        num = 0
        if stream:
            num = self.snext[stream] = self.snext.get(stream, 0) + 1
        off, first = 0, True
        while True:
            n = min(len(msg) - off, MAX_PART)
            self.queue.append(Part(self.next, msg[off:off + n], off + n < len(msg), zip_, stream,
                                   num if first else 0, bool(stream) and first))
            first = False
            self.next += 1
            off += n
            if off >= len(msg):
                return

    def next_packet(self, now: float, force_ack: bool = False):
        """The next packet content and whether it is a retransmission, or None."""
        p = None
        lowest = min(self.inflight) if self.inflight else 0
        for x in self.inflight.values():
            if now - x.sent >= self._timeout(x, x.seq - lowest) and (p is None or x.seq < p.seq):
                p = x
        retry = False
        if p is not None:
            retry = True
            self._lost(now)
        elif self.queue and self.can_send():
            p = self.queue.pop(0)
            self.inflight[p.seq] = p
            self.inflight_bytes += len(p.data)
        received = self.recv_ack > 1 or bool(self.got)
        ack = received and (p is not None or force_ack or (self.ack_due and now >= self.ack_due))
        if p is None and not ack:
            return None
        flags = 0
        b = bytearray(b"\x00")
        if ack:
            flags |= F_ACK
            self._append_ack(b)
            self.ack_due, self.unacked = 0.0, 0
        if p is not None:
            flags |= F_MSG | (F_MORE if p.more else 0) | (F_ZIP if p.zip else 0)
            put_uvarint(b, p.seq)
            if p.first_of_stream:
                flags |= F_FIRST
                put_uvarint(b, p.stream)
                put_uvarint(b, p.num)
            elif p.stream:
                flags |= F_CONT
            b += p.data
            if not p.first:
                p.first = now
            p.delivered = self.delivered
            p.sent = now
            p.tries += 1
        b[0] = flags
        return bytes(b), retry

    def _append_ack(self, b: bytearray):
        put_uvarint(b, self.recv_ack - 1)
        above = sorted(k for k in self.got if k > self.recv_ack)
        ranges = bytearray()
        count, cursor, i = 0, self.recv_ack, 0
        while i < len(above):
            j = i
            while j + 1 < len(above) and above[j + 1] == above[j] + 1:
                j += 1
            r = bytearray()
            put_uvarint(r, above[i] - cursor)
            put_uvarint(r, j - i + 1)
            if len(ranges) + len(r) > ACK_BUDGET - 12:
                break
            ranges += r
            count += 1
            cursor = above[j] + 1
            i = j + 1
        put_uvarint(b, count)
        b += ranges

    def receive(self, now: float, b: bytes, deliver) -> None:
        """deliver(msg, zip, stream) for each message as it becomes deliverable."""
        if not b:
            raise ValueError("empty packet")
        flags, pos = b[0], 1
        if flags & F_ACK:
            upto, pos = read_uvarint(b, pos)
            count, pos = read_uvarint(b, pos)
            if count > 64:
                raise ValueError("too many ranges")
            done = 0
            newest = 0.0  # the latest send time among the parts this ack covers

            def ack(seq):
                nonlocal done, newest
                p = self.inflight.get(seq)
                if p is None:
                    return
                newest = max(newest, p.sent)
                self.delivered += len(p.data)
                if p.tries == 1:
                    dt = now - p.sent
                    self._sample(dt)
                    if dt > 0:
                        self._rate(now, (self.delivered - p.delivered) / dt)
                del self.inflight[seq]
                self.inflight_bytes -= len(p.data)
                done += 1

            for seq in [s for s in self.inflight if s <= upto]:
                ack(seq)
            beyond, cursor = 0, upto + 1
            for _ in range(count):
                gap, pos = read_uvarint(b, pos)
                run, pos = read_uvarint(b, pos)
                start = cursor + gap
                for seq in range(start, start + run):
                    ack(seq)
                beyond += run
                cursor = start + run
            self._acked(done)
            if newest:  # time-based loss detection (RACK): sent well before one that arrived
                reorder = max(self.srtt / 4, 0.001)
                lost = False
                for p in self.inflight.values():
                    if p.sent and p.sent + reorder < newest:
                        p.sent, lost = 0.0, True
                if lost:
                    self._lost(now)
            if beyond:
                gap = self.inflight.get(upto + 1)
                if gap and (beyond >= 3 or now - gap.sent >= max(self.srtt / 4, ACK_DELAY)):
                    gap.sent = 0.0
        if not flags & F_MSG:
            return
        seq, pos = read_uvarint(b, pos)
        r = RPart(bool(flags & F_MORE), bool(flags & F_ZIP))
        if flags & F_FIRST:
            r.stream, pos = read_uvarint(b, pos)
            r.num, pos = read_uvarint(b, pos)
            r.first = r.streamed = True
        elif flags & F_CONT:
            r.streamed = True
        if not self.ack_due:
            self.ack_due = now + ACK_DELAY
        self.unacked += 1
        if self.unacked >= 2 or seq != self.recv_ack:
            self.ack_due = now
        if seq < self.recv_ack or seq in self.got or len(self.got) >= GOT_MAX:
            return
        r.data = bytes(b[pos:])
        self.got[seq] = r
        while self.recv_ack in self.got:
            self.recv_ack += 1
        if r.streamed:
            self._assemble(seq, deliver)
        self._take0(deliver)
        for k in [k for k, x in self.got.items() if x.used and k < self.recv_ack and k < self.next0]:
            del self.got[k]

    def _assemble(self, seq, deliver):
        start = seq
        while True:
            x = self.got.get(start)
            if x is None or x.used:
                return
            if x.first:
                break
            if not x.streamed or start == 0:
                return
            start -= 1
        head = self.got[start]
        parts, end = [], start
        while True:
            x = self.got.get(end)
            if x is None or not x.streamed or x.used or (end != start and x.first):
                return
            parts.append(x.data)
            if not x.more:
                break
            end += 1
        for k in range(start, end + 1):
            self.got[k].used = True
        st = self.streams.setdefault(head.stream, [1, {}])
        if head.num < st[0]:
            return
        st[1][head.num] = (b"".join(parts), head.zip)
        while st[0] in st[1]:
            msg, z = st[1].pop(st[0])
            st[0] += 1
            deliver(msg, z, head.stream)

    def _take0(self, deliver):
        while True:
            x = self.got.get(self.next0)
            if x is None:
                return
            self.next0 += 1
            if x.streamed:
                continue
            x.used = True
            if not self.asm0:
                self.zip0 = x.zip
            if self.asm0_len + len(x.data) > MSG_MAX:
                self.asm0, self.asm0_len = [], 0
                continue
            self.asm0.append(x.data)
            self.asm0_len += len(x.data)
            if x.more:
                continue
            msg = b"".join(self.asm0)
            self.asm0, self.asm0_len = [], 0
            deliver(msg, self.zip0, 0)

    def idle(self) -> bool:
        return not self.inflight and not self.queue

    def stuck(self) -> bool:
        return any(p.tries >= 4 for p in self.inflight.values())


def keepalive() -> bytes:
    return bytes((F_ONCE,))
