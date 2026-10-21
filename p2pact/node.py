"""Node: a device in a P2PACT network (spec §1–§8) — pairing, sessions over any road,
delivery, messages and compression. Runs on an asyncio event loop."""
import asyncio
import concurrent.futures
import os
import struct
import sys
import time

from .cbor import decode, decode_array_raw, encode
from . import learn
from .compress import ZIP_MIN, Dict, DictStore, compress, decompress, dict_id
from .crypto import address, random_bytes
from .delivery import DATA_HEADER, MSG_MAX, Stream, keepalive
from .learn import History, history_path
from .noise import Handshake
from .roads import TCPRoad, UDPRoad
from .store import PROLOGUE, Identity, Invite, Peer, Trust, hints_from_wire, hints_to_wire

P_INIT, P_RESP, P_PAIR1, P_PAIR2, P_PAIR3, P_DATA, P_RESET = 1, 2, 3, 4, 5, 6, 7
TS_SKEW_NS = 120 * 10**9
INIT_EVERY, AUTO_CONNECT, ALIVE_FOR, KEEPALIVE_GAP, SESSION_IDLE = 1.0, 30.0, 60.0, 25.0, 180.0

ERR_NO_METHOD, ERR_BAD_ARGS, ERR_NOT_FOUND, ERR_FORBIDDEN, ERR_FAILED, ERR_NOT_DELIVERED = 1, 2, 3, 4, 5, 6


class P2PACTError(Exception):
    def __init__(self, code: int, text: str):
        super().__init__(text)
        self.code = code


def _u32(b: bytes, at: int) -> int:
    return int.from_bytes(b[at:at + 4], "big")


def _be32(v: int) -> bytes:
    return (v & 0xFFFFFFFF).to_bytes(4, "big")


def _goos() -> str:
    return {"win32": "windows", "darwin": "darwin"}.get(sys.platform, sys.platform)


def _key(ep) -> str:
    return ep[0].name + "|" + ep[1]


class _Window:
    def __init__(self):
        self.top, self.seen = 0, set()

    def accept(self, n: int) -> bool:
        if n + 1 > self.top:
            self.seen = {x for x in self.seen if x + 2048 > n}
            self.top = n + 1
        elif self.top - n > 2048 or n in self.seen:
            return False
        self.seen.add(n)
        return True


class _Session:
    def __init__(self, peer, local, remote, send, recv, now):
        self.peer, self.local, self.remote, self.send, self.recv = peer, local, remote, send, recv
        self.send_n, self.win, self.last_recv = 0, _Window(), now


class _PeerState:
    def __init__(self, addr: str):
        self.addr = addr
        self.st = Stream()
        self.eps: dict[str, dict] = {}
        self.last_ts = 0
        self.boot = 0
        self.last_init = 0.0
        self.calls: dict[int, asyncio.Future] = {}
        self.call_id = 0
        self.dicts: list[bytes] = []  # its dictionaries (ids) by slot — from its hello and 0.5
        self.lacks: list[bytes] = []  # it asked us for these, so it lacks them until it announces again
        self.waiting: list[tuple[bytes, bool, int]] = []  # waiting for a dictionary: run in order once it arrives
        self.fetching = False
        self.tried: list[bytes] = []  # dictionaries of its list we asked it for and did not get
        self.hist: History | None = None  # what we sent it and got from it, to train our dictionary for it
        self.sys_calls: set[int] = set()  # our calls of tool 0: their results are not conversation
        self.queue: list[tuple[bytes, bool, int, int]] = []  # conversation waiting to be learnt: msg, heard, plain, zips
        self.queued = 0
        self.last_talk = 0.0


class Node:
    def __init__(self, dir_: str, name: str):
        self.name = name
        self.dir = dir_
        self.id = Identity.load(dir_)
        self.trust = Trust(dir_)
        self.dicts = DictStore(dir_)
        self.on_event = self.on_paired = self.on_hello = self.allow_dict = None
        self.no_compression = False  # what we send goes uncompressed (benchmarks, debugging)
        self.no_learning = False  # do not train our own dictionaries on what we send (spec §5)
        self.trainer: concurrent.futures.ThreadPoolExecutor | None = None  # one dictionary at a time
        self.closed = False
        self.boot = int.from_bytes(random_bytes(4), "big") or 1
        self.udp: UDPRoad | None = None
        self.tcp: TCPRoad | None = None
        self.sessions: dict[int, _Session] = {}
        self.current: dict[str, _Session] = {}
        self.hs: dict[int, dict] = {}
        self.invites: dict[str, Invite] = {}
        self.peers: dict[str, _PeerState] = {}
        self.handlers: dict[tuple[int, int], object] = {}
        self.reset_at: dict[str, float] = {}
        self.tasks: list[asyncio.Task] = []
        self.woken = False
        self.handshakes = 0
        self.handle(0, 1, lambda peer, args: [])
        self.handle(0, 2, lambda peer, args: self._info(peer))
        self.handle(0, 5, self._dict_handler)

    async def listen_udp(self, addr: str):
        self.udp = await UDPRoad.listen(addr, self._receive)

    async def listen_tcp(self, addr: str):
        """The fallback road; "" — dial only."""
        self.tcp = await TCPRoad.listen(addr, self._receive)

    def start(self):
        async def every(dt, f):
            while True:
                await asyncio.sleep(dt)
                f()
        loop = asyncio.get_running_loop()
        self.tasks = [loop.create_task(every(0.02, self._pump)), loop.create_task(every(1.0, self._maintain)),
                      loop.create_task(every(learn.LEARN_TICK, self._learn_tick))]

    def close(self):
        self.closed = True
        if self.trainer:
            self.trainer.shutdown(wait=False, cancel_futures=True)
        for t in self.tasks:
            t.cancel()
        for r in (self.udp, self.tcp):
            if r:
                r.close()
        for ps in self.peers.values():
            for f in ps.calls.values():
                if not f.done():
                    f.set_exception(ConnectionError("node closed"))

    def handle(self, tool: int, method: int, h):
        """h(peer, raw_args) -> list of result values (or an awaitable of it)."""
        self.handlers[(tool, method)] = h

    # --- pairing ---

    def invite(self, ttl: float) -> Invite:
        inv = Invite(self.id.key[1], self.name, random_bytes(32), time.time() + ttl, self._hints())
        self.invites[inv.id.hex()] = inv
        return inv

    async def join(self, inv: Invite, timeout: float = 30.0) -> Peer:
        eps = []
        if self.udp:
            eps += [(self.udp, a) for a in inv.hints.get("udp", [])]
        if self.tcp:
            eps += [(self.tcp, a) for a in inv.hints.get("tcp", [])]
        if not eps:
            raise P2PACTError(ERR_FAILED, "the invite has no road we can use")
        deadline = time.monotonic() + timeout
        local = 0
        loop = asyncio.get_running_loop()
        while True:
            self.hs.pop(local, None)
            hs = Handshake("XXpsk2", True, PROLOGUE, self.id.key, psk=inv.secret)
            msg1 = hs.write_message()
            local = self._new_index()
            done = loop.create_future()
            self.hs[local] = {"pair": True, "hs": hs, "invite": inv, "done": done, "at": time.time(), "early": []}
            pkt = bytes((P_PAIR1,)) + inv.id + _be32(local) + msg1
            for road, a in eps:
                road.send(a, pkt)
            try:
                await asyncio.wait_for(asyncio.shield(done), INIT_EVERY)
                p = self.trust.get(address(inv.key))
                if not p:
                    raise P2PACTError(ERR_FAILED, "pairing was not saved")
                return p
            except asyncio.TimeoutError:
                if time.monotonic() > deadline:
                    self.hs.pop(local, None)
                    raise P2PACTError(ERR_FAILED, "pairing timed out")

    def _pair_payload(self) -> bytes:
        return encode([self.name, self.boot, hints_to_wire(self._hints()), self.id.sign_public, _goos()])

    def befriend(self, p: Peer):
        if len(p.key) != 32 or address(p.key) != p.addr:
            raise ValueError("key does not match address")
        old = self.trust.get(p.addr)
        if old:
            old.name, old.sign_key, old.os = p.name, p.sign_key, p.os
            self.trust.put(old)
            return
        p.pair_secret = self.id.shared(p.key, "family-pair")
        self.trust.put(p)

    def forget(self, addr: str):
        """Drops a known device; our conversation's dictionaries and history go too."""
        self.dicts.forget(addr)
        ps = self.peers.get(addr)
        if ps and ps.hist:
            ps.hist.gone = True
        try:
            os.remove(history_path(self.dir, addr))
        except OSError:
            pass
        self.peers.pop(addr, None)
        s = self.current.pop(addr, None)
        if s:
            self.sessions.pop(s.local, None)
        self.trust.remove(addr)

    # --- calls and events ---

    async def call(self, peer: str, tool: int, method: int, *args) -> list[bytes]:
        """Calls tool.method on a known device (stream 0, in order); raw CBOR result elements."""
        return await self.call_on(peer, 0, tool, method, *args)

    async def call_on(self, peer: str, stream: int, tool: int, method: int, *args) -> list[bytes]:
        """call on a stream: ordered within it, independent of other streams (one per chat)."""
        ps = self._peer(peer)
        if not ps:
            raise P2PACTError(ERR_FAILED, "unknown device")
        ps.call_id += 1
        cid = ps.call_id
        fut = asyncio.get_running_loop().create_future()
        ps.calls[cid] = fut
        if tool == 0:
            ps.sys_calls.add(cid)
        try:
            self._push(ps, encode([0, cid, tool, method, *args]), stream, tool != 0)
            return await fut
        finally:
            ps.calls.pop(cid, None)
            ps.sys_calls.discard(cid)

    def event(self, peer: str, tool: int, ev: int, *args):
        self.event_on(peer, 0, tool, ev, *args)

    def event_on(self, peer: str, stream: int, tool: int, ev: int, *args):
        ps = self._peer(peer)
        if not ps:
            raise P2PACTError(ERR_FAILED, "unknown device")
        self._push(ps, encode([3, tool, ev, *args]), stream, tool != 0)

    def paths(self, peer: str) -> list[str]:
        ps = self.peers.get(peer)
        if not ps:
            return []
        now = time.time()
        out = []
        for e in ps.eps.values():
            if now - e["last_recv"] <= ALIVE_FOR and e["ep"][0].name not in out:
                out.append(e["ep"][0].name)
        return out

    def _info(self, peer: str):
        """The hello (spec §6, 0.2); the dictionaries are those peer may see, by slot."""
        tools = {t: 1 for (t, _m) in self.handlers if t != 0}
        return [self.name, _goos(), "p2pact-py", tools, self.dicts.ids(peer), hints_to_wire(self._hints())]

    def _hints(self) -> dict:
        h = {}
        if self.udp and (u := self.udp.local_addrs()):
            h["udp"] = u
        if self.tcp and (t := self.tcp.local_addrs()):
            h["tcp"] = t
        return h

    # --- receiving ---

    def _receive(self, pkt: bytes, frm):
        if len(pkt) < 5:
            return
        now = time.time()
        try:
            {P_DATA: self._on_data, P_INIT: self._on_init, P_RESP: self._on_resp, P_PAIR1: self._on_pair1,
             P_PAIR2: self._on_pair2, P_PAIR3: self._on_pair3, P_RESET: self._on_reset}.get(pkt[0], lambda *a: None)(
                now, bytes(pkt), frm)
        except Exception:
            pass  # a malformed packet is dropped

    def _on_reset(self, now, pkt, frm):
        idx = _u32(pkt, 1)
        for s in list(self.sessions.values()):
            if s.remote == idx:
                self.sessions.pop(s.local, None)
                if self.current.get(s.peer) is s:
                    del self.current[s.peer]

    def _on_data(self, now, pkt, frm):
        if len(pkt) < DATA_HEADER + 16:
            return
        idx = _u32(pkt, 1)
        s = self.sessions.get(idx)
        if not s:
            h = self.hs.get(idx)
            if h and not h["pair"] and len(h["early"]) < 16:
                h["early"].append((pkt, frm))  # data overtook the handshake reply
                return
            k = _key(frm)
            if now - self.reset_at.get(k, 0) >= 5:
                self.reset_at[k] = now
                frm[0].send(frm[1], bytes((P_RESET,)) + _be32(idx))
            return
        cnt = _u32(pkt, 5)
        plain = s.recv.decrypt_at(cnt, pkt[:DATA_HEADER], pkt[DATA_HEADER:])
        if plain is None or not s.win.accept(cnt):
            return
        s.last_recv = now
        self.current.setdefault(s.peer, s)
        ps = self._peer(s.peer)
        self._seen(ps, frm, now, s.local)
        ps.st.receive(now, plain, lambda m, z, st: self._inbound(s.peer, m, z, st))
        if ps.st.ack_due and now >= ps.st.ack_due:
            self._wake()

    def _on_init(self, now, pkt, frm):
        hs = Handshake("IK", False, PROLOGUE, self.id.key)
        payload = hs.read_message(pkt[5:])
        if len(payload) < 12:
            return
        peer = address(hs.rs)
        if not self.trust.get(peer):
            return  # silence to strangers
        ps = self._peer(peer)
        ts = int.from_bytes(payload[:8], "big")
        age = int(now * 1e9) - ts
        if ts <= ps.last_ts or abs(age) > TS_SKEW_NS:
            return
        ps.last_ts = ts
        local = self._new_index()
        resp = hs.write_message(_be32(self.boot))
        c1, c2 = hs.ciphers
        s = _Session(peer, local, _u32(pkt, 1), c2, c1, now)
        self.sessions[local] = s
        self.current[peer] = s
        self.handshakes += 1
        self._seen(ps, frm, now, s.local)
        self._boot(ps, _u32(payload, 8))
        frm[0].send(frm[1], bytes((P_RESP,)) + _be32(s.remote) + _be32(local) + resp)
        if len(payload) > 12:
            ps.st.receive(now, payload[12:], lambda m, z, st: self._inbound(peer, m, z, st))
        self._send_info(peer)

    def _on_resp(self, now, pkt, frm):
        if len(pkt) < 9:
            return
        local = _u32(pkt, 1)
        h = self.hs.get(local)
        if not h or h["pair"]:
            return
        payload = h["hs"].read_message(pkt[9:])
        if len(payload) < 4 or not h["hs"].ciphers:
            return
        del self.hs[local]
        c1, c2 = h["hs"].ciphers
        s = _Session(h["peer"], local, _u32(pkt, 5), c1, c2, now)
        self.sessions[local] = s
        self.current[h["peer"]] = s
        self.handshakes += 1
        ps = self._peer(h["peer"])
        self._seen(ps, frm, now, s.local)
        self._boot(ps, _u32(payload, 0))
        self._send_info(h["peer"])
        for p, f in h["early"]:
            self._on_data(now, p, f)

    def _on_pair1(self, now, pkt, frm):
        if len(pkt) < 21:
            return
        inv = self.invites.get(pkt[1:17].hex())
        if not inv or now > inv.exp:
            return
        hs = Handshake("XXpsk2", False, PROLOGUE, self.id.key, psk=inv.secret)
        hs.read_message(pkt[21:])
        msg2 = hs.write_message(self._pair_payload())
        local = self._new_index()
        remote = _u32(pkt, 17)
        self.hs[local] = {"pair": True, "hs": hs, "invite": inv, "done": None, "at": now, "remote": remote, "early": []}
        frm[0].send(frm[1], bytes((P_PAIR2,)) + _be32(remote) + _be32(local) + msg2)

    def _peer_from_payload(self, key, pp, inv, via=None) -> Peer:
        hints = hints_from_wire(pp[2] if len(pp) > 2 else None)
        if via is None:
            for k in ("udp", "tcp", "relay"):
                if not hints.get(k) and inv.hints.get(k):
                    hints[k] = inv.hints[k]
        return Peer(address(key), bytes(key), str(pp[0] or ""), inv.secret, hints, 0,
                    pp[3] if len(pp) > 3 and isinstance(pp[3], bytes) else None,
                    pp[4] if len(pp) > 4 and isinstance(pp[4], str) else None, via)

    def _on_pair2(self, now, pkt, frm):
        if len(pkt) < 9:
            return
        local = _u32(pkt, 1)
        h = self.hs.get(local)
        if not h or not h["pair"] or h["done"] is None:
            return
        try:
            payload = h["hs"].read_message(pkt[9:])
        except Exception:
            return  # wrong secret or a stranger
        inv = h["invite"]
        if h["hs"].rs != inv.key:
            del self.hs[local]
            if not h["done"].done():
                h["done"].set_exception(P2PACTError(ERR_FAILED, "device key does not match the invite"))
            return
        pp = decode(payload)
        msg3 = h["hs"].write_message(self._pair_payload())
        c1, c2 = h["hs"].ciphers
        del self.hs[local]
        p = self._peer_from_payload(inv.key, pp, inv)
        self.trust.put(p)
        s = _Session(p.addr, local, _u32(pkt, 5), c1, c2, now)
        self.sessions[local] = s
        self.current[p.addr] = s
        ps = self._peer(p.addr)
        self._seen(ps, frm, now, s.local)
        self._boot(ps, int(pp[1] or 0))
        frm[0].send(frm[1], bytes((P_PAIR3,)) + _be32(s.remote) + msg3)
        self._paired(p)
        if not h["done"].done():
            h["done"].set_result(None)

    def _on_pair3(self, now, pkt, frm):
        local = _u32(pkt, 1)
        h = self.hs.get(local)
        if not h or not h["pair"] or h["done"] is not None:
            return
        payload = h["hs"].read_message(pkt[5:])
        if not h["hs"].ciphers:
            return
        c1, c2 = h["hs"].ciphers
        del self.hs[local]
        inv = h["invite"]
        self.invites.pop(inv.id.hex(), None)  # single use
        pp = decode(payload)
        p = self._peer_from_payload(h["hs"].rs, pp, inv, via=inv.id.hex())
        self.trust.put(p)
        s = _Session(p.addr, local, h["remote"], c2, c1, now)
        self.sessions[local] = s
        self.current[p.addr] = s
        ps = self._peer(p.addr)
        self._seen(ps, frm, now, s.local)
        self._boot(ps, int(pp[1] or 0))
        self._paired(p)

    def _paired(self, p: Peer):
        self._send_info(p.addr)
        if self.on_paired:
            asyncio.get_running_loop().call_soon(self.on_paired, p)

    def _boot(self, ps: _PeerState, boot: int):
        if ps.boot and ps.boot != boot:
            ps.st.reset()
        ps.boot = boot

    def _send_info(self, peer: str):
        self._push(self._peer(peer), encode([3, 0, 2, *self._info(peer)]))

    def _message(self, peer: str, msg: bytes, stream: int = 0):
        try:
            a = decode_array_raw(msg)
        except Exception:
            return
        if len(a) < 2:
            return
        kind = decode(a[0])
        ps = self._peer(peer)
        if not ps:
            return
        if kind == 0 and len(a) >= 4:
            cid, tool, args = decode(a[1]), decode(a[2]), a[4:]
            h = self.handlers.get((tool, decode(a[3])))
            if tool != 0:
                self._hear(ps, msg)

            async def run():
                if h is None:
                    out = [2, cid, ERR_NO_METHOD, "no such method"]
                else:
                    try:
                        r = h(peer, args)
                        if asyncio.iscoroutine(r):
                            r = await r
                        out = [1, cid, *r]
                    except P2PACTError as e:
                        out = [2, cid, e.code, str(e)]
                    except Exception as e:
                        out = [2, cid, ERR_FAILED, str(e)]
                ps2 = self._peer(peer)
                if ps2:
                    self._push(ps2, encode(out), stream, tool != 0)  # the result goes back on the call's stream
            asyncio.get_running_loop().create_task(run())
        elif kind in (1, 2):
            cid = decode(a[1])
            fut = ps.calls.get(cid)
            if not fut or fut.done():
                return
            if cid not in ps.sys_calls:
                self._hear(ps, msg)
            if kind == 1:
                fut.set_result(a[2:])
            else:
                fut.set_exception(P2PACTError(int(decode(a[2])) if len(a) > 2 else ERR_FAILED,
                                              str(decode(a[3])) if len(a) > 3 else ""))
        elif kind == 3 and len(a) >= 3:
            tool, ev = decode(a[1]), decode(a[2])
            if tool == 0 and ev == 2 and len(a) >= 9:
                self.trust.set_hints(peer, str(decode(a[3]) or ""), str(decode(a[4]) or ""), hints_from_wire(decode(a[8])))
                ps.dicts, ps.lacks, ps.tried = _ids(decode(a[7])), [], []
                self._fetch_new(peer, ps)
                self._drain(peer, ps)
                if self.on_hello:
                    asyncio.get_running_loop().call_soon(self.on_hello, peer)
                return
            if tool == 0 and ev == 5 and len(a) >= 4:  # the dictionary list changed
                ps.dicts, ps.lacks, ps.tried = _ids(decode(a[3])), [], []
                self._fetch_new(peer, ps)
                self._drain(peer, ps)
                return
            if tool != 0:
                self._hear(ps, msg)
            if self.on_event:
                asyncio.get_running_loop().call_soon(self.on_event, peer, tool, ev, a[3:])

    # --- sending ---

    def _peer(self, peer: str) -> _PeerState | None:
        ps = self.peers.get(peer)
        if ps is None and self.trust.get(peer):
            ps = self.peers[peer] = _PeerState(peer)
        return ps

    def _seen(self, ps, frm, now, session):
        e = ps.eps.setdefault(_key(frm), {"ep": frm, "last_recv": 0.0, "last_send": 0.0, "session": 0})
        e["last_recv"], e["session"] = now, session

    def _candidates(self, peer, ps, now, all_: bool) -> list[dict]:
        alive = [e for e in ps.eps.values() if now - e["last_recv"] <= ALIVE_FOR]
        cur = self.current.get(peer)
        if cur and not all_:  # roads of the current session: earlier ones may be gone
            mine = [e for e in alive if e.get("session") == cur.local]
            if mine:
                alive = mine
        if alive and not all_:
            rank = lambda e: {"udp": 0, "tcp": 1}.get(e["ep"][0].name, 2)
            # the road heard from last; a better kind only if heard within half a second of it
            best = max(alive, key=lambda e: e["last_recv"])
            for e in alive:
                if rank(e) < rank(best) and best["last_recv"] - e["last_recv"] < 0.5:
                    best = e
            return [best]
        out = alive
        p = self.trust.get(peer)
        if not p:
            return out
        for road, addrs in ((self.udp, p.hints.get("udp")), (self.tcp, p.hints.get("tcp"))):
            if not road:
                continue
            for a in addrs or []:
                e = ps.eps.setdefault(_key((road, a)), {"ep": (road, a), "last_recv": 0.0, "last_send": 0.0, "session": 0})
                if e not in out:
                    out.append(e)
        return out

    def _send_data(self, now, peer, ps, s, plain, all_):
        hdr = bytes((P_DATA,)) + _be32(s.remote) + _be32(s.send_n)
        pkt = hdr + s.send.encrypt_at(s.send_n, hdr, plain)
        s.send_n += 1
        for e in self._candidates(peer, ps, now, all_):
            e["ep"][0].send(e["ep"][1], pkt)
            e["last_send"] = now

    def _start_init(self, now, peer, ps, first: bytes | None):
        p = self.trust.get(peer)
        if not p or now - ps.last_init < _init_gap(ps):
            return
        ps.last_init = now
        # keep the last few unanswered starts: a reply to any of them opens the session
        pending = sorted((h["at"], i) for i, h in self.hs.items() if not h["pair"] and h.get("peer") == peer)
        while len(pending) >= 3:
            del self.hs[pending.pop(0)[1]]
        hs = Handshake("IK", True, PROLOGUE, self.id.key, rs=p.key)
        msg1 = hs.write_message(struct.pack(">Q", int(now * 1e9)) + _be32(self.boot) + (first or b""))
        local = self._new_index()
        self.hs[local] = {"pair": False, "hs": hs, "peer": peer, "at": now, "early": []}
        pkt = bytes((P_INIT,)) + _be32(local) + msg1
        for e in self._candidates(peer, ps, now, True):
            e["ep"][0].send(e["ep"][1], pkt)
            e["last_send"] = now

    def _wake(self):
        if self.woken:
            return
        self.woken = True

        def run():
            self.woken = False
            self._pump()
        asyncio.get_running_loop().call_soon(run)

    def _pump(self):
        now = time.time()
        for peer, ps in list(self.peers.items()):
            s = self.current.get(peer)
            if not s:
                if not ps.st.idle() and now - ps.last_init >= _init_gap(ps) and self.trust.get(peer):
                    nxt = ps.st.next_packet(now)
                    self._start_init(now, peer, ps, nxt[0] if nxt else None)
                continue
            if not ps.st.idle() and now - s.last_recv > 10 and ps.st.stuck():
                del self.current[peer]
                continue
            c = self._candidates(peer, ps, now, False)
            if len(c) == 1:
                ps.st.reliable = c[0]["ep"][0].name != "udp"
            for i in range(257):
                if i == 256:
                    self._wake()
                    break
                nxt = ps.st.next_packet(now)
                if not nxt:
                    break
                self._send_data(now, peer, ps, s, nxt[0], nxt[1])
            for e in ps.eps.values():
                if now - e["last_recv"] <= ALIVE_FOR and now - e["last_send"] >= KEEPALIVE_GAP:
                    hdr = bytes((P_DATA,)) + _be32(s.remote) + _be32(s.send_n)
                    e["ep"][0].send(e["ep"][1], hdr + s.send.encrypt_at(s.send_n, hdr, keepalive()))
                    s.send_n += 1
                    e["last_send"] = now

    def _maintain(self):
        now = time.time()
        for p in self.trust.list():
            ps = self._peer(p.addr)
            if ps and p.addr not in self.current and now - ps.last_init >= AUTO_CONNECT:
                self._start_init(now, p.addr, ps, None)
        for idx, s in list(self.sessions.items()):
            if self.current.get(s.peer) is not s and now - s.last_recv > SESSION_IDLE:
                del self.sessions[idx]
        for idx, h in list(self.hs.items()):
            if now - h["at"] > 60:
                del self.hs[idx]
        for k, inv in list(self.invites.items()):
            if now > inv.exp:
                del self.invites[k]

    def _new_index(self) -> int:
        while True:
            i = int.from_bytes(os.urandom(4), "big")
            if i and i not in self.sessions and i not in self.hs:
                return i

    # --- compression (spec §5) ---

    def _push(self, ps: _PeerState, msg: bytes, stream: int = 0, talk: bool = False):
        """Queues a message, compressed when worth it: with our dictionary for this device if it
        has it, else the newest one it also has. The slot refers to our list at send time: the
        list changes only through event 0.5, which travels in the same order as messages.
        talk: the message is conversation (not tool 0), so it goes to the history."""
        if self.no_compression:
            ps.st.push(msg, False, stream)
            self._wake()
            return
        d, slot = self.dicts.pick(ps.addr, ps.dicts, ps.lacks)
        z = compress(msg, d, slot)
        if talk:
            self._learn(ps, msg, d, z)
        if z:
            ps.st.push(z, True, stream)
        else:
            ps.st.push(msg, False, stream)
        self._wake()

    def _inbound(self, peer: str, msg: bytes, zip_: bool, stream: int = 0):
        """Decompresses a reassembled message and runs it in order. A missing dictionary is not
        an error: we hold the message and everything after it and ask the sender for it; if we
        do not know the sender's list yet (it restarted), we wait for its hello. While waiting,
        only replies to our calls (the dictionary among them), hellos and dictionary lists run
        out of order: nothing depends on their order."""
        ps = self._peer(peer)
        if not ps:
            return
        if ps.waiting:
            plain, _ = self._unzip(ps, msg, zip_)
            if plain is not None and _out_of_order(plain):
                self._message(peer, plain, stream)
                self._drain(peer, ps)
                return
        ps.waiting.append((msg, zip_, stream))
        self._drain(peer, ps)

    def _drain(self, peer, ps):
        """Runs waiting messages in order until one cannot be decoded yet."""
        while ps.waiting:
            msg, zip_, stream = ps.waiting[0]
            plain, why = self._unzip(ps, msg, zip_)
            if why == "missing":
                if id_ := ps.dicts[msg[0] - 1]:
                    self._fetch_dict(peer, ps, id_, True)
                    return
                why = "bad"  # a free slot: the message is damaged
            if why == "nolist":
                return  # wait for a hello or 0.5
            ps.waiting.pop(0)
            if plain is not None:
                self._message(peer, plain, stream)

    def _unzip(self, ps, msg, zip_):
        """The message decompressed, or None and why: "missing" — we lack the dictionary in that
        slot, "nolist" — the slot is beyond the list we know, "bad"."""
        if not zip_:
            return msg, None
        if not msg:
            return None, "bad"
        d = None
        slot = msg[0]
        if slot > 0:
            if slot > len(ps.dicts):
                return None, "nolist"
            d = self.dicts.get(ps.dicts[slot - 1], ps.addr)
            if d is None:
                return None, "missing"
        try:
            return decompress(msg, d, MSG_MAX), None
        except Exception:
            return None, "bad"

    def _fetch_new(self, peer, ps):
        """Asks the device for the newest dictionary in its list that we lack: so it can compress
        with it (only a dictionary both have is used). One at a time; one we could not get (the
        family's, say) is not asked for again until its list changes."""
        for id_ in reversed(ps.dicts):  # by slot: the newest go last
            if id_ and self.dicts.get(id_, peer) is None and id_ not in ps.tried:
                self._fetch_dict(peer, ps, id_, False)
                return

    def _fetch_dict(self, peer, ps, id_: bytes, waiting: bool):
        """Asks the device for dictionary id_: one it compressed a waiting message with (it has
        it), or a new one in its list. What we get belongs to the pair with it."""
        if ps.fetching:
            return
        ps.fetching = True

        async def run():
            d = None
            for _ in range(3):
                try:
                    res = await asyncio.wait_for(self.call(peer, 0, 5, id_), 30)
                    raw = decode(res[0])
                    if isinstance(raw, bytes) and dict_id(raw) == id_:
                        d = Dict(raw, peer)
                        break
                except Exception:
                    pass
            ps.fetching = False
            if self.closed or self.peers.get(peer) is not ps:
                return
            if d and not self._add_dict(d):  # could not store it: do not ask again and again
                d = None
            if d is None:
                if waiting and ps.waiting:
                    ps.waiting.pop(0)  # unreachable dictionary: this message is lost
                else:
                    ps.tried.append(id_)
            self._drain(peer, ps)
            self._fetch_new(peer, ps)
        asyncio.get_running_loop().create_task(run())

    def _dict_handler(self, peer: str, args: list[bytes]):
        """0.5 dict [id] → dictionary bytes. A device that asks lacks it, so we stop compressing
        with it for that device (this reply included) until it announces again."""
        id_ = decode(args[0]) if args else None
        if not isinstance(id_, bytes):
            raise P2PACTError(ERR_BAD_ARGS, "dictionary id required")
        if self.allow_dict and not self.allow_dict(peer, id_):
            raise P2PACTError(ERR_FORBIDDEN, "dictionary is for the family only")
        if peer in self.peers:
            self.peers[peer].lacks.append(id_)
        d = self.dicts.get(id_, peer)
        if not d:
            raise P2PACTError(ERR_NOT_FOUND, "no such dictionary")
        return [d.raw]

    def add_dict(self, raw: bytes):
        """Stores a new (newest) common dictionary and announces it to the known devices."""
        if not self._add_dict(Dict(raw)):
            raise P2PACTError(ERR_FAILED, "could not store the dictionary")

    def _add_dict(self, d: Dict) -> bool:
        """Stores a dictionary and announces the new list (event 0.5) to the devices that see
        it: all for a common one, the pair's device for its own. Only over a live session: a new
        one starts with our hello, which carries the list."""
        try:
            self.dicts.add(d)
        except OSError:
            return False
        for p in self.trust.list():
            if not d.visible(p.addr) or p.addr not in self.current:
                continue
            ps = self._peer(p.addr)
            if ps:
                ps.st.push(encode([3, 0, 5, self.dicts.ids(p.addr)]), False)
        self._wake()
        return True

    def dicts_for(self, peer: str) -> list[bytes]:
        """The dictionary ids peer sees, by slot."""
        return self.dicts.ids(peer)

    def dict_state(self, peer: str) -> tuple[bytes | None, bytes | None, bool]:
        """What compresses messages to peer: own — our newest dictionary trained for it (None —
        none yet), using — the one used now (None — plain zstd), training — a new one is due or
        being trained, or messages wait to be learnt."""
        d = self.dicts.own(peer)
        own = d.id if d else None
        using, training = None, False
        ps = self.peers.get(peer)
        if ps:
            u, _ = self.dicts.pick(peer, ps.dicts, ps.lacks)
            using = u.id if u else None
            training = bool(ps.queue) or bool(ps.hist and (ps.hist.training or ps.hist.due))
        return own, using, training

    # --- our own dictionaries (spec §5, learn.py) ---

    def _hear(self, ps: _PeerState, msg: bytes):
        """Queues a conversation message we got from the device."""
        if not self.no_compression:
            self._queue(ps, msg, True, 0, 0)

    def _learn(self, ps: _PeerState, msg: bytes, d: Dict | None, z: bytes | None):
        """Queues a conversation message we send; d and z are the dictionary it was compressed
        with and the result (None — sent as is)."""
        plain = zips = 0
        if d and d.own:
            plain, zips = len(msg), len(z) if z else len(msg)
        self._queue(ps, msg, False, plain, zips)

    def _queue(self, ps, msg, heard, plain, zips):
        if self.no_learning or len(msg) < ZIP_MIN or ps.queued >= learn.LEARN_QUEUE_MAX:
            return
        ps.queue.append((msg, heard, plain, zips))
        ps.queued += min(len(msg), learn.LEARN_SAMPLE)
        ps.last_talk = time.monotonic()

    def _history(self, ps: _PeerState) -> History:
        if ps.hist:
            return ps.hist
        h = ps.hist = History.load(history_path(self.dir, ps.addr))
        if d := self.dicts.own(ps.addr):
            h.trained = h.size()
            try:
                h.at = os.stat(os.path.join(self.dicts.dir, d.id.hex())).st_mtime
            except OSError:
                pass
        return h

    def _learn_tick(self):
        """Takes the queues into the histories and trains when it is time."""
        for ps in list(self.peers.values()):
            if not ps.queue and not (ps.hist and ps.hist.due):
                continue
            q, ps.queue, ps.queued = ps.queue, [], 0
            h = self._history(ps)
            for msg, heard, plain, zips in q:
                m = bytes(msg[:learn.LEARN_SAMPLE])
                h.add(m, heard)
                h.save(m, heard)
                h.plain += plain
                h.zips += zips
            h.flush()
            self._consider(ps, h)

    def _consider(self, ps: _PeerState, h: History):
        """Decides whether a new dictionary is due and trains it in a lull."""
        if h.training:
            return
        now, wall = time.monotonic(), time.time()
        own = self.dicts.own(ps.addr)
        size = h.size()
        if h.plain >= learn.LEARN_WINDOW:  # compression over the last window of what we sent with it
            ratio = h.zips / h.plain
            h.plain = h.zips = 0
            if h.base == 0:
                h.base = ratio
            elif ratio >= h.base * learn.LEARN_WORSE:
                h.worse = True
        if not h.due and len(h.own) >= learn.LEARN_OWN_MIN:
            if own is None:
                if size >= max(learn.LEARN_FIRST, 2 * h.trained):  # trained: a try that failed
                    h.due = "first"
            elif size < learn.LEARN_FIRST:
                pass  # too little to replace what we have (the history was lost, say)
            elif h.trained < learn.LEARN_MAX and size >= 2 * h.trained:
                h.due = "doubled"
            elif wall - h.checked >= learn.LEARN_CHECK:
                h.checked = wall
                if wall - h.at > learn.LEARN_MONTH or h.worse:
                    h.due = "check"
            if h.due:
                h.due_at = now
        if not h.due or (now - ps.last_talk < learn.LEARN_LULL and now - h.due_at < learn.LEARN_WAIT):
            return
        h.due, h.worse, h.training = "", False, True
        own_msgs, heard = h.samples()
        if not self.trainer:
            self.trainer = concurrent.futures.ThreadPoolExecutor(1, thread_name_prefix="p2pact-train")
        try:
            fut = asyncio.get_running_loop().run_in_executor(
                self.trainer, learn.train, own_msgs, heard, min(learn.LEARN_DICT_MAX, max(size // 4, 4 << 10)))
        except RuntimeError:  # closed meanwhile
            h.training = False
            return

        def done(f):
            # a failure waits like a success: until the history doubles or the next check
            h.training, h.trained, h.at = False, size, time.time()
            if self.closed or h.gone or f.cancelled() or f.exception():
                return
            d = f.result()
            d.peer, d.own = ps.addr, True
            if self._add_dict(d):
                h.plain = h.zips = 0
                h.base = 0.0
        fut.add_done_callback(done)


def _init_gap(ps) -> float:
    """Retry a handshake after three measured round trips (0.25–2 s), else after a second."""
    return INIT_EVERY if ps.st.srtt == 0 else min(max(3 * ps.st.srtt, 0.25), 2.0)


def _ids(v) -> list[bytes]:
    return [x for x in v if isinstance(x, bytes)] if isinstance(v, list) else []


def _out_of_order(m: bytes) -> bool:
    if len(m) < 2:
        return False
    return m[1] in (1, 2) or (len(m) > 3 and m[1] == 3 and m[2] == 0 and m[3] in (2, 5))
