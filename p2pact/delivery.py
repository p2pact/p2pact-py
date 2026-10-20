"""Delivery (spec §5): flags | [ack: varint up-to + varint bitmap] | [varint part number | part].
Messages go in packet-sized parts, acknowledged and retransmitted; congestion control as in
TCP NewReno with HyStart, timers per RFC 6298, a delivery-rate limit as in BBR."""

F_ACK, F_MSG, F_MORE, F_ZIP, F_ONCE = 1, 2, 4, 8, 16
MAX_PACKET = 1200
DATA_HEADER = 9
MAX_PART = MAX_PACKET - DATA_HEADER - 16 - 1 - 10 - 5
RTO_START, RTO_MIN, RTO_MAX = 0.5, 0.05, 4.0
ACK_DELAY = 0.04
CWND_START = CWND_MIN = 32
CWND_MAX = 4096
EARLY_MAX = 512
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
    __slots__ = ("seq", "data", "more", "zip", "first", "sent", "tries", "delivered")

    def __init__(self, seq, data, more, zip_):
        self.seq, self.data, self.more, self.zip = seq, data, more, zip_
        self.first = self.sent = 0.0
        self.tries = self.delivered = 0


class Stream:
    def __init__(self):
        self.next = 1
        self.inflight: dict[int, Part] = {}
        self.queue: list[Part] = []
        self.cwnd, self.ssthresh = float(CWND_START), float(CWND_MAX)
        self.srtt = self.rttvar = self.min_rtt = self.last_cut = 0.0
        self.delivered, self.bw, self.bw_at = 0, 0.0, 0.0
        self.inflight_bytes, self.reliable = 0, False
        self.recv_next = 1
        self.early: dict[int, Part] = {}
        self.assembling: list[bytes] = []
        self.assembled = 0
        self.zipped = False
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
        for _ in range(1, p.tries):
            if t >= RTO_MAX:
                break
            t *= 2
        return min(t, RTO_MAX)

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
        for _ in range(n):
            self.cwnd += 1 if self.cwnd < self.ssthresh else 1 / self.cwnd
        self.cwnd = min(self.cwnd, CWND_MAX)

    def _lost(self, now):
        if now - self.last_cut < max(self.srtt, RTO_MIN):
            return
        self.last_cut = now
        self.ssthresh = max(self.cwnd / 2, CWND_MIN)
        self.cwnd = self.ssthresh

    def reset(self):
        pending = sorted(self.inflight.values(), key=lambda p: p.seq) + self.queue
        self.next, self.inflight, self.queue, self.inflight_bytes = 1, {}, [], 0
        for p in pending:
            p.seq, p.first, p.sent, p.tries, p.delivered = self.next, 0.0, 0.0, 0, 0
            self.next += 1
            self.queue.append(p)
        self.recv_next, self.early, self.assembling, self.assembled = 1, {}, [], 0
        self.zipped, self.ack_due, self.unacked = False, 0.0, 0

    def push(self, msg: bytes, zip_: bool):
        off = 0
        while True:
            n = min(len(msg) - off, MAX_PART)
            self.queue.append(Part(self.next, msg[off:off + n], off + n < len(msg), zip_))
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
        ack = self.recv_next > 1 and (p is not None or force_ack or (self.ack_due and now >= self.ack_due))
        if p is None and not ack:
            return None
        flags = 0
        b = bytearray(b"\x00")
        if ack:
            flags |= F_ACK
            put_uvarint(b, self.recv_next - 1)
            bits = 0
            for i in range(32):
                if self.recv_next + 1 + i in self.early:
                    bits |= 1 << i
            put_uvarint(b, bits)
            self.ack_due, self.unacked = 0.0, 0
        if p is not None:
            flags |= F_MSG | (F_MORE if p.more else 0) | (F_ZIP if p.zip else 0)
            put_uvarint(b, p.seq)
            b += p.data
            if not p.first:
                p.first = now
            p.delivered = self.delivered
            p.sent = now
            p.tries += 1
        b[0] = flags
        return bytes(b), retry

    def receive(self, now: float, b: bytes, deliver) -> None:
        if not b:
            raise ValueError("empty packet")
        flags, pos = b[0], 1
        if flags & F_ACK:
            upto, pos = read_uvarint(b, pos)
            bits, pos = read_uvarint(b, pos)
            done = 0

            def ack(seq):
                nonlocal done
                p = self.inflight.get(seq)
                if p is None:
                    return
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
            ones = 0
            for i in range(32):
                if bits & (1 << i):
                    ones += 1
                    ack(upto + 2 + i)
            self._acked(done)
            if bits:
                gap = self.inflight.get(upto + 1)
                if gap and (ones >= 3 or now - gap.sent >= max(self.srtt / 4, ACK_DELAY)):
                    gap.sent = 0.0
        if not flags & F_MSG:
            return
        seq, pos = read_uvarint(b, pos)
        data = b[pos:]
        if not self.ack_due:
            self.ack_due = now + ACK_DELAY
        self.unacked += 1
        if self.unacked >= 2 or seq != self.recv_next:
            self.ack_due = now
        if seq < self.recv_next:
            return
        if seq > self.recv_next:
            if len(self.early) < EARLY_MAX:
                self.early[seq] = Part(seq, bytes(data), bool(flags & F_MORE), bool(flags & F_ZIP))
            return
        self._take(bytes(data), bool(flags & F_MORE), bool(flags & F_ZIP), deliver)
        while self.recv_next in self.early:
            p = self.early.pop(self.recv_next)
            self._take(p.data, p.more, p.zip, deliver)

    def _take(self, data, more, zip_, deliver):
        self.recv_next += 1
        if not self.assembling:
            self.zipped = zip_
        if self.assembled + len(data) > MSG_MAX:
            self.assembling, self.assembled = [], 0
            return
        self.assembling.append(data)
        self.assembled += len(data)
        if more:
            return
        msg = b"".join(self.assembling)
        self.assembling, self.assembled = [], 0
        deliver(msg, self.zipped)

    def idle(self) -> bool:
        return not self.inflight and not self.queue

    def stuck(self) -> bool:
        return any(p.tries >= 4 for p in self.inflight.values())


def keepalive() -> bytes:
    return bytes((F_ONCE,))
