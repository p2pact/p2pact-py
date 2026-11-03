"""Node: a device in a P2PACT network (spec §1–§8) — pairing, sessions over any road,
delivery, messages and compression. Runs on an asyncio event loop."""
import asyncio
import concurrent.futures
import inspect
import os
import stat
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
from .plugin import ENV_INVITE, ENV_SOCKET
from .roads import LocalRoad, TCPRoad, UDPRoad, local_supported
from .grants import (LEVEL_READ, LEVEL_WRITE, Grant, clean_grants, default_grants, grant_level, grants_wire, is_default_grants,
                     parse_grants)
from .tools import FIRST_NAMED_TOOL, FIXED_TOOLS, valid_tool_name
from .store import PROLOGUE, Identity, Invite, Peer, Trust, hints_from_wire, hints_to_wire

P_INIT, P_RESP, P_PAIR1, P_PAIR2, P_PAIR3, P_DATA, P_RESET = 1, 2, 3, 4, 5, 6, 7
TS_SKEW_NS = 120 * 10**9
INIT_EVERY, AUTO_CONNECT, ALIVE_FOR, KEEPALIVE_GAP, SESSION_IDLE = 1.0, 30.0, 60.0, 25.0, 180.0
HOLD_ASK, HOLD_DROP = 15.0, 120.0  # held messages: ask again, then drop them (_unhold)

ERR_NO_METHOD, ERR_BAD_ARGS, ERR_NOT_FOUND, ERR_FORBIDDEN, ERR_FAILED, ERR_NOT_DELIVERED = 1, 2, 3, 4, 5, 6


# Kinds of device (spec §1): what a device is for, told in the pairing payload and the hello.
KIND_UNKNOWN = 0  # not said (an older device): guess as before, e.g. by OS
KIND_COMPUTER = 1  # runs agents, serves tools
KIND_CLIENT = 2  # an app a person holds: a phone, a desktop or web app
KIND_PLUGIN = 3  # a program on the same computer that adds tools to it


class P2PACTError(Exception):
    def __init__(self, code: int, text: str):
        super().__init__(text)
        self.code = code


class Later:
    """A reply taken out of the stream's turn: see later()."""
    __slots__ = ("reply",)

    def __init__(self, reply):
        self.reply = reply


def later(reply) -> Later:
    """Answers a call later (spec §6): a handler returns later(reply), its turn on the stream ends
    there, so the stream's next calls and events run (a cancel among them), and the call's result
    or error goes when reply — an awaitable of the result values — is done, unless the caller
    restarted meanwhile.

        node.handle(1, 1, lambda peer, args: later(run_turn(args)))
    """
    return Later(reply)


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
        self.heard = False  # it knows our boot id: sent us session data or answered our handshake
        self.last_init = 0.0
        self.calls: dict[int, asyncio.Future] = {}
        self.call_id = 0
        self.dicts: list[bytes] = []  # its dictionaries (ids) by slot — from its hello and 0.5
        self.lacks: list[bytes] = []  # it asked us for these, so it lacks them until it announces again
        self.waiting: list[tuple[bytes, bool, int]] = []  # waiting for a dictionary: run in order once it arrives
        self.wait_since = 0.0  # when the head of waiting started to wait (_unhold unblocks it)
        self.fetching = False
        self.asking_info = False  # our 0.2 info call is on its way (_ask_info)
        self.asked_info = 0.0  # when we asked
        self.tried: list[bytes] = []  # dictionaries of its list we asked it for and did not get
        self.hist: History | None = None  # what we sent it and got from it, to train our dictionary for it
        self.sys_calls: set[int] = set()  # our calls of tool 0: their results are not conversation
        self.queue: list[tuple[bytes, bool, int, int]] = []  # conversation waiting to be learnt: msg, heard, plain, zips
        self.queued = 0
        self.last_talk = 0.0
        self.inbox: dict[int, list] = {}  # calls and events waiting for their turn, per stream
        self.named: dict[str, tuple[int, int]] = {}  # its named tools {name: (number, version)}, from its hello (spec §8)


class Node:
    def __init__(self, dir_: str, name: str):
        self.name = name
        self.dir = dir_
        self.id = Identity.load(dir_)
        self.trust = Trust(dir_)
        self.dicts = DictStore(dir_)
        # on_event(peer, tool, ev, raw_args) receives tool events (except tool 0): in the order
        # sent on each stream, one at a time, together with that stream's calls (spec §6)
        self.on_event = self.on_paired = self.on_hello = self.allow_dict = None
        # on_wants(peer, wants) -> (grants, ok) is called on the inviting device when a newcomer
        # has paired (spec §2), with what it asks to use (everything, if it did not say): the
        # application shows it to its person and returns what the newcomer is granted, or ok
        # False to refuse (the newcomer is forgotten). It may be a coroutine function and wait
        # for the person; the newcomer can use nothing meanwhile. on_paired follows when it
        # accepts. None — the newcomer gets what it asked for.
        self.on_wants = None
        # on_held(peer, held) is called when messages from a device waited too long for a
        # dictionary or its list and were dropped (held — how many): the application can tell
        # the user or resend
        self.on_held = None
        self.hints_sent: bytes | None = None  # our addresses as last announced (_reannounce)
        self.hints_at = 0.0  # when last checked
        self._later: set = set()  # replies given later (spec §6): their tasks, kept until done
        self.no_compression = False  # what we send goes uncompressed (benchmarks, debugging)
        self.no_learning = False  # do not train our own dictionaries on what we send (spec §5)
        self.kind = KIND_UNKNOWN  # what this device is for, told in pairing and the hello (spec §1)
        self.trainer: concurrent.futures.ThreadPoolExecutor | None = None  # one dictionary at a time
        self.closed = False
        self.boot = int.from_bytes(random_bytes(4), "big") or 1
        self.udp: UDPRoad | None = None
        self.tcp: TCPRoad | None = None
        self.loc: LocalRoad | None = None  # the local socket road (spec §3)
        self.local_path = ""  # the socket we listen on, or dial
        # invites made for programs (plugin_invite) → the grants their install gave
        self.invite_grants: dict[str, list[Grant]] = {}
        self.sessions: dict[int, _Session] = {}
        self.current: dict[str, _Session] = {}
        self.hs: dict[int, dict] = {}
        self.invites: dict[str, Invite] = {}
        self.peers: dict[str, _PeerState] = {}
        self.handlers: dict[tuple[int, int], object] = {}
        # grants (spec §8.1): methods that check the level themselves, methods marked read
        self.level_handlers: dict[tuple[int, int], object] = {}
        self.read_methods: set[tuple[int, int]] = set()
        self.tool_handlers: dict[int, object] = {}  # one handler for all methods of a tool (handle_tool_all)
        # on_granted(peer, grants) is called when a known device tells what we may use of its tools (event 0.6)
        self.on_granted = None
        # named tools (spec §8): name → number and back, versions
        self.names: dict[str, int] = {}
        self.numbers: dict[int, str] = {}
        self.versions: dict[int, int] = {}
        self.reset_at: dict[str, float] = {}
        self.tasks: list[asyncio.Task] = []
        self.woken = False
        self.handshakes = 0
        self.handle(0, 1, lambda peer, args: [])
        self.handle(0, 2, lambda peer, args: self._info(peer))
        self.handle(0, 5, self._dict_handler)
        self.handle(0, 6, lambda peer, args: [grants_wire(self.grants(peer))])

    async def listen_udp(self, addr: str):
        self.udp = await UDPRoad.listen(addr, self._receive)

    async def listen_tcp(self, addr: str):
        """The fallback road; "" — dial only."""
        self.tcp = await TCPRoad.listen(addr, self._receive)

    async def listen_local(self, path: str):
        """Opens the local socket (spec §3) at path: a Unix domain socket readable and writable by
        our OS user only (mode 0600). Programs on this computer (a plugin, a CLI) pair with the
        node and talk to it over it. An old socket file nobody listens on is replaced."""
        _need_local()
        if not path:
            raise P2PACTError(ERR_FAILED, "no socket path")
        if self.loc is not None:
            raise P2PACTError(ERR_FAILED, "the local socket is already in use")
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(st.st_mode):
                raise P2PACTError(ERR_FAILED, path + " is not a socket")
            try:
                _, w = await asyncio.wait_for(asyncio.open_unix_connection(path), 1)
            except (OSError, asyncio.TimeoutError):
                os.remove(path)  # nobody listens: a leftover of a crash
            else:
                w.close()
                raise P2PACTError(ERR_FAILED, path + " is in use")
        try:
            self.loc = await LocalRoad.listen(path, self._receive)
        except OSError as e:
            raise P2PACTError(ERR_FAILED, str(e))
        self.local_path = path

    def use_local(self, path: str):
        """Makes the node reach a device on this computer over its local socket at path: join()
        and the session use it. The node does not listen."""
        _need_local()
        if not path:
            raise P2PACTError(ERR_FAILED, "no socket path")
        if self.loc is not None:
            raise P2PACTError(ERR_FAILED, "the local socket is already in use")
        self.loc, self.local_path = LocalRoad(self._receive), path

    def _is_local(self, frm) -> bool:
        """A packet that came over our local socket."""
        return self.loc is not None and frm[0] is self.loc

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
        for r in (self.udp, self.tcp, self.loc):
            if r:
                r.close()
        for ps in self.peers.values():
            for f in ps.calls.values():
                if not f.done():
                    f.set_exception(ConnectionError("node closed"))

    def handle(self, tool: int, method: int, h):
        """h(peer, raw_args) -> list of result values (or an awaitable of it). Calls of one device
        on one stream run one at a time, in the order sent, together with its events there
        (spec §6); other streams do not wait. A handler that waits long returns later(...), so
        that the stream goes on without it."""
        self.handlers[(tool, method)] = h

    # --- grants (spec §8.1) ---

    def handle_level(self, tool: int, method: int, h):
        """Registers tool.method like handle(), for a handler that checks the level itself:
        h(peer, level, raw_args) with level 1 (read) or 2 (write). The node only requires read.
        For a tool whose single method carries many (chat 1.1: one P2PACT method for all of
        ACP), where what a call needs depends on its arguments."""
        self.level_handlers[(tool, method)] = h

    def mark_read(self, tool: int, *methods: int):
        """Declares methods of a tool as read (spec §8.1): a device with read on the tool may
        call them. The others are write."""
        self.read_methods.update((tool, m) for m in methods)

    def grants(self, peer: str) -> list[Grant]:
        """What we let a device use of ours (spec §8.1); [] for an unknown device."""
        p = self.trust.get(peer)
        return p.allowed() if p else []

    def granted_by(self, peer: str) -> list[Grant]:
        """What a device lets us use of its tools, as it told us (event 0.6 or method 0.6); the
        default if it never did."""
        p = self.trust.get(peer)
        return p.offered() if p else []

    def level(self, peer: str, tool: str) -> int:
        """The level a device has on one of our tools, by name."""
        p = self.trust.get(peer)
        return grant_level(p.grants, tool) if p else 0

    def set_grants(self, peer: str, grants):
        """Replaces what a trusted device may use (an empty list revokes everything), keeps it
        with the trust and tells the device with event 0.6."""
        grants = clean_grants(grants)
        if not self.trust.set_grants(peer, grants):
            raise P2PACTError(ERR_FAILED, "unknown device")
        self.event(peer, 0, 6, grants_wire(grants))

    def grant(self, peer: str, tool: str, level: int):
        """Changes one entry: the device gets level on the tool (LEVEL_READ, LEVEL_WRITE);
        level 0 removes the entry."""
        p = self.trust.get(peer)
        if not p:
            raise P2PACTError(ERR_FAILED, "unknown device")
        grants = [g for g in p.allowed() if g.tool != tool]
        if level > 0:
            grants.append(Grant(tool, level))
        self.set_grants(peer, grants)

    def revoke_grants(self, peer: str):
        """Takes everything away from a device but tool 0: it stays trusted and in session."""
        self.set_grants(peer, [])

    def _grants_event(self, peer: str):
        """Tells the device what it may use, unless that is the default it assumes."""
        p = self.trust.get(peer)
        if p is None or is_default_grants(p.grants):
            return
        self._push(self._peer(peer), encode([3, 0, 6, grants_wire(p.grants)]))

    def _required_level(self, tool: int, method: int) -> int:
        """The level a call needs."""
        if ((tool, method) in self.level_handlers or (tool, method) in self.read_methods
                or (tool in self.tool_handlers and (tool, method) not in self.handlers)):
            return LEVEL_READ
        return LEVEL_WRITE

    # --- named tools (spec §8) ---

    def register_tool(self, name: str, version: int = 1) -> int:
        """Gives a tool of ours a name and picks its number: the first one from 64 up that no
        other tool of ours uses. The same name keeps its number for the rest of the run. The
        number is announced in the hello's named map, and the devices in session get the new
        hello at once. Other devices may number the same name differently: callers use
        tool_number()."""
        if not valid_tool_name(name):
            raise ValueError("bad tool name: " + name)
        if (num := self.names.get(name)) is not None:
            if self.versions[num] != version:
                self.versions[num] = version
                self._reannounce_tools()
            return num
        num = FIRST_NAMED_TOOL
        while self._tool_used(num):
            num += 1
        self.names[name], self.numbers[num], self.versions[num] = num, name, version
        self._reannounce_tools()
        return num

    def _tool_used(self, num: int) -> bool:
        return num in self.numbers or any(t == num for (t, _m) in self.handlers)

    def _reannounce_tools(self):
        for peer in list(self.current):
            self._send_info(peer)

    def handle_tool(self, name: str, method: int, h):
        """handle() by tool name (the tool is registered at version 1 if it is not yet)."""
        num = FIXED_TOOLS.get(name)
        if num is None:
            num = self.register_tool(name, 1)
        self.handle(num, method, h)

    def handle_tool_all(self, name: str, h):
        """Serves every method of the named tool with h(peer, level, method, raw_args) (the tool
        is registered at version 1 if it is not yet). The node only requires read on the tool;
        what each method needs is for h to check. Methods registered one by one with handle()
        keep their own handlers. For a device that hosts another program's tool (spec §8.2)."""
        self.tool_handlers[self.register_tool(name, 1)] = h

    def unregister_tool(self, name: str):
        """Takes a named tool back: it leaves the hello (sent again to the devices in session)
        and its handlers are dropped. Registering the name again may give another number."""
        num = self.names.pop(name, None)
        if num is None:
            return
        self.numbers.pop(num, None)
        self.versions.pop(num, None)
        self.tool_handlers.pop(num, None)
        for table in (self.handlers, self.level_handlers):
            for k in [k for k in table if k[0] == num]:
                del table[k]
        self.read_methods = {k for k in self.read_methods if k[0] != num}
        self._reannounce_tools()

    def peer_tools(self, peer: str) -> list[str]:
        """The named tools a device announced in its hello, sorted by name."""
        ps = self.peers.get(peer)
        return sorted(ps.named) if ps else []

    def tool_name(self, tool: int) -> str:
        """The name of a tool of ours by its number ("" — it has none: a number of the
        implementation's own)."""
        for name, num in FIXED_TOOLS.items():
            if num == tool:
                return name
        return self.numbers.get(tool, "")

    def tool_number(self, peer: str, name: str) -> int | None:
        """Resolves a tool name to the number the device announced for it in its hello (spec
        §8); the tools of the spec have their fixed numbers. None — the device has not announced
        it (or we have not heard its hello yet)."""
        if (num := FIXED_TOOLS.get(name)) is not None:
            return num
        ps = self.peers.get(peer)
        ref = ps.named.get(name) if ps else None
        return ref[0] if ref else None

    def peer_tool_name(self, peer: str, tool: int) -> str:
        """The name of a tool of a device by the number it announced: what an on_event handler
        needs ("" — unnamed)."""
        for name, num in FIXED_TOOLS.items():
            if num == tool:
                return name
        ps = self.peers.get(peer)
        for name, ref in (ps.named.items() if ps else ()):
            if ref[0] == tool:
                return name
        return ""

    async def call_tool(self, peer: str, name: str, method: int, *args) -> list[bytes]:
        """call() by tool name: the number is the device's own."""
        return await self.call_tool_on(peer, 0, name, method, *args)

    async def call_tool_on(self, peer: str, stream: int, name: str, method: int, *args) -> list[bytes]:
        """call_on() by tool name."""
        num = self.tool_number(peer, name)
        if num is None:
            raise P2PACTError(ERR_NO_METHOD, "the device has no tool " + name)
        return await self.call_on(peer, stream, num, method, *args)

    def _named(self) -> dict:
        """The hello's named map: {name: [tool, version]}."""
        return {name: [num, self.versions[num]] for name, num in self.names.items()}

    # --- pairing ---

    def invite(self, ttl: float) -> Invite:
        inv = Invite(self.id.key[1], self.name, random_bytes(32), time.time() + ttl, self._hints())
        self.invites[inv.id.hex()] = inv
        return inv

    def plugin_invite(self, ttl: float, grants=()) -> Invite:
        """The invite for a program the device starts (spec §2): single use, no hints (the
        program reaches the device over the local socket), valid for ttl seconds, and the
        program is granted exactly grants: the install gave them, nobody is asked. The program
        must pair with kind KIND_PLUGIN over the local socket; it is never added to the family
        and never reached over another road."""
        inv = Invite(self.id.key[1], self.name, random_bytes(32), time.time() + ttl, {})
        self.invites[inv.id.hex()] = inv
        self.invite_grants[inv.id.hex()] = clean_grants(grants)
        return inv

    def plugin_env(self, ttl: float, grants=()) -> dict[str, str]:
        """plugin_invite() and the environment to start the program with: P2PACT_SOCKET and
        P2PACT_INVITE. The node must listen on its local socket."""
        if not self.local_path or self.loc is None:
            raise P2PACTError(ERR_FAILED, "the node does not listen on a local socket")
        return {ENV_SOCKET: self.local_path, ENV_INVITE: str(self.plugin_invite(ttl, grants))}

    async def join(self, inv: Invite, timeout: float = 30.0, wants=None) -> Peer:
        """Pairs using an invite, trying all its hints until one answers. wants asks for
        permissions (spec §2): what we want to use on the inviting device. Its person may narrow
        it; the result comes back as event 0.6 (granted_by(), on_granted). None — we ask for
        everything, as between one person's own devices."""
        eps = []
        if self.udp:
            eps += [(self.udp, a) for a in inv.hints.get("udp", [])]
        if self.tcp:
            eps += [(self.tcp, a) for a in inv.hints.get("tcp", [])]
        if self.loc and self.local_path:  # a device on this computer, over its socket
            eps.append((self.loc, self.local_path))
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
            self.hs[local] = {"pair": True, "hs": hs, "invite": inv, "done": done, "at": time.time(), "early": [],
                             "wants": wants}
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

    async def join_wants(self, inv: Invite, wants, timeout: float = 30.0) -> Peer:
        """join() asking for permissions (spec §2, `wants`)."""
        return await self.join(inv, timeout, wants)

    def _pair_payload(self, wants=None) -> bytes:
        """[name, boot, hints, signing key, os, kind, wants]. wants are what we ask to use (None
        — not asking, the field is left out, and so is the kind if we do not say one: an older
        device gets what it knows)."""
        a = [self.name, self.boot, hints_to_wire(self._hints()), self.id.sign_public, _goos()]
        if self.kind != KIND_UNKNOWN or wants is not None:
            a.append(self.kind)
        if wants is not None:
            a.append(grants_wire(clean_grants(wants)))
        return encode(a)

    def befriend(self, p: Peer):
        if p.kind == KIND_PLUGIN:
            raise ValueError("a plugin is never in the family")
        if len(p.key) != 32 or address(p.key) != p.addr:
            raise ValueError("key does not match address")
        old = self.trust.get(p.addr)
        if old:
            old.name, old.sign_key, old.os = p.name, p.sign_key, p.os
            if p.kind != KIND_UNKNOWN:
                old.kind = p.kind
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
        if tool != 0:  # a tool's events go only to devices with at least read on it (spec §8.1)
            p = self.trust.get(peer)
            if grant_level(p.grants if p else None, self.tool_name(tool)) < LEVEL_READ:
                return
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
        # tools whose handlers check the caller's level are tools too
        tools = {t: 1 for (t, _m) in (*self.handlers, *self.level_handlers) if t != 0 and t not in self.numbers}
        return [self.name, _goos(), "p2pact-py", tools, self.dicts.ids(peer), hints_to_wire(self._hints()), self.kind,
                self._named()]

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
        ps.heard = True
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
        known = self.trust.get(peer)
        if not known:
            return  # silence to strangers
        if known.kind == KIND_PLUGIN and not self._is_local(frm):
            return  # a plugin is reachable over the local socket only (spec §2)
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
        # data in the first packet; from a device that has not heard our boot id it may be
        # numbered for our previous boot, to be renumbered once it gets our reply: drop it
        # unacknowledged, it comes again in the session (spec §4.2)
        if len(payload) > 12 and ps.heard:
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
        ps.heard = True
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
                    pp[4] if len(pp) > 4 and isinstance(pp[4], str) else None, via, _pair_kind(pp))

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
        msg3 = h["hs"].write_message(self._pair_payload(h.get("wants")))
        c1, c2 = h["hs"].ciphers
        del self.hs[local]
        p = self._peer_from_payload(inv.key, pp, inv)
        p.local = self._is_local(frm)
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
        inv = h["invite"]
        pp = decode(payload)
        kind = _pair_kind(pp)
        for_program = inv.id.hex() in self.invite_grants
        if (kind == KIND_PLUGIN or for_program) and (kind != KIND_PLUGIN or not self._is_local(frm)):
            return  # a plugin pairs over the local socket only, with an invite made for programs (spec §2)
        del self.hs[local]
        self.invites.pop(inv.id.hex(), None)  # single use
        p = self._peer_from_payload(h["hs"].rs, pp, inv, via=inv.id.hex())
        # what the newcomer may use (spec §2): without wants it asks for everything and keeps the
        # default; with them, and no on_wants to narrow them, it gets what it asked. With
        # on_wants the application decides: until it does the newcomer may use nothing.
        wants = parse_grants(pp[6]) if len(pp) > 6 else None
        ask = False
        if wants is not None:
            p.grants = clean_grants(wants)
        if self.on_wants:
            ask, p.grants = True, []
        if for_program:  # the install gave the grants: nobody is asked
            ask, p.grants = False, clean_grants(self.invite_grants[inv.id.hex()])
        if kind == KIND_PLUGIN:  # reachable over the local socket only
            p.hints = {}
        self.invite_grants.pop(inv.id.hex(), None)
        self.trust.put(p)
        s = _Session(p.addr, local, h["remote"], c2, c1, now)
        self.sessions[local] = s
        self.current[p.addr] = s
        ps = self._peer(p.addr)
        self._seen(ps, frm, now, s.local)
        self._boot(ps, int(pp[1] or 0))
        if ask:
            self._send_info(p.addr)
            asyncio.get_running_loop().create_task(self._decide_wants(p, clean_grants(wants) if wants is not None
                                                                       else default_grants()))
            return
        self._paired(p)

    async def _decide_wants(self, p: Peer, wants: list[Grant]):
        try:
            r = self.on_wants(p, wants)
            if inspect.isawaitable(r):
                r = await r
            grants, ok = r
        except Exception:
            ok = False  # an application that fails refuses
        if not ok:
            self.forget(p.addr)
            return
        if not self.trust.get(p.addr):
            return  # forgotten while the person was deciding
        self.set_grants(p.addr, grants)
        if self.on_paired:
            self.on_paired(self.trust.get(p.addr))

    def _paired(self, p: Peer):
        self._send_info(p.addr)
        if self.on_paired:
            asyncio.get_running_loop().call_soon(self.on_paired, p)

    def _boot(self, ps: _PeerState, boot: int):
        if ps.boot and ps.boot != boot:
            ps.st.reset()
        ps.boot = boot

    def _send_info(self, peer: str):
        self.hints_sent = encode(hints_to_wire(self._hints()))  # what the devices know of us (_reannounce)
        self._push(self._peer(peer), encode([3, 0, 2, *self._info(peer)]))
        self._grants_event(peer)

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
            cid, tool, method, args = decode(a[1]), decode(a[2]), decode(a[3]), a[4:]
            h = self.handlers.get((tool, method))
            level, forbidden = 0, False
            if tool != 0:  # grants (spec §8.1): tool 0 is always allowed
                p = self.trust.get(peer)
                level = grant_level(p.grants if p else None, self.tool_name(tool))
                forbidden = level < self._required_level(tool, method)
            if (lh := self.level_handlers.get((tool, method))) and not forbidden:
                h = lambda peer, args: lh(peer, level, args)
            elif (th := self.tool_handlers.get(tool)) and h is None and not forbidden:
                h = lambda peer, args: th(peer, level, method, args)
            if tool != 0:
                self._hear(ps, msg)
            boot = ps.boot

            async def reply(r):
                try:
                    if isinstance(r, Exception):
                        raise r
                    if inspect.isawaitable(r):
                        r = await r
                    out = [1, cid, *r]
                except P2PACTError as e:
                    out = [2, cid, e.code, str(e)]
                except Exception as e:
                    out = [2, cid, ERR_FAILED, str(e)]
                # the result goes back on the call's stream, unless the caller restarted meanwhile
                ps2 = self._peer(peer)
                if ps2 and (boot == 0 or ps2.boot == boot):
                    if tool == 0 and method == 2:  # a hello, like the event: never compressed
                        ps2.st.push(encode(out), False, stream, True)
                        self._wake()
                    else:
                        self._push(ps2, encode(out), stream, tool != 0, reply=True)

            async def run():
                if forbidden:
                    return await reply(P2PACTError(ERR_FORBIDDEN, "forbidden"))
                if h is None:
                    return await reply(P2PACTError(ERR_NO_METHOD, "no such method"))
                try:
                    r = h(peer, args)
                    if inspect.isawaitable(r) and not isinstance(r, Later):
                        r = await r
                except Exception as e:
                    return await reply(e)
                if isinstance(r, Later):  # the turn ends here; the reply goes when it is ready
                    t = asyncio.get_running_loop().create_task(reply(r.reply))
                    self._later.add(t)
                    t.add_done_callback(self._later.discard)
                    return
                await reply(r)
            if tool == 0:  # service calls (a dictionary, a ping) never wait behind a slow handler
                asyncio.get_running_loop().create_task(run())
            else:
                self._inbox(ps, stream, run)
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
                if len(a) >= 10 and _is_int(k := decode(a[9])):
                    self.trust.set_kind(peer, k)
                ps.named = {}
                if len(a) >= 11 and isinstance(named := decode(a[10]), dict):
                    for nm, v in named.items():
                        if isinstance(nm, str) and isinstance(v, list) and len(v) >= 2 and _is_int(v[0]) and _is_int(v[1]):
                            ps.named[nm] = (v[0], v[1])
                ps.dicts, ps.lacks, ps.tried = _ids(decode(a[7])), [], []
                self._fetch_new(peer, ps)
                self._drain(peer, ps)
                if self.on_hello:
                    asyncio.get_running_loop().call_soon(self.on_hello, peer)
                return
            if tool == 0 and ev == 6 and len(a) >= 4:  # what we may use of its tools
                if (g := parse_grants(decode(a[3]))) is not None:
                    self.trust.set_granted(peer, g)
                    if self.on_granted:
                        asyncio.get_running_loop().call_soon(self.on_granted, peer, g)
                return
            if tool == 0 and ev == 5 and len(a) >= 4:  # the dictionary list changed
                ps.dicts, ps.lacks, ps.tried = _ids(decode(a[3])), [], []
                self._fetch_new(peer, ps)
                self._drain(peer, ps)
                return
            if tool != 0:
                self._hear(ps, msg)
            if on := self.on_event:
                args = a[3:]
                self._inbox(ps, stream, lambda: on(peer, tool, ev, args))

    async def after_events(self, peer: str, stream: int = 0):
        """Waits until the events and calls that came from a device on a stream before now have
        been handled (on_event ran for them). A call's result may be delivered ahead of the
        events queued before it; a caller that needs them all waits here."""
        ps = self._peer(peer)
        if not ps:
            return
        done = asyncio.get_running_loop().create_future()
        self._inbox(ps, stream, lambda: done.done() or done.set_result(None))
        await done

    def _inbox(self, ps: _PeerState, stream: int, f):
        """Queues f behind the stream's earlier calls and events: they run one at a time, in the
        order they came (spec §6). Each stream has its own worker while it has work, so a slow
        handler holds up its own stream only. f may return an awaitable."""
        q = ps.inbox.get(stream)
        if q is not None:
            q.append(f)
            return
        q = ps.inbox[stream] = [f]

        async def work():
            try:
                while q:
                    g = q.pop(0)
                    try:
                        r = g()
                        if asyncio.iscoroutine(r) or isinstance(r, asyncio.Future):
                            await r
                    except Exception:
                        pass  # a failing event handler does not stop the stream
            finally:
                if ps.inbox.get(stream) is q:
                    del ps.inbox[stream]
        asyncio.get_running_loop().create_task(work())

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
            rank = lambda e: {"udp": 0, "tcp": 1, "local": 1}.get(e["ep"][0].name, 2)
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

        def add(road, a):
            e = ps.eps.setdefault(_key((road, a)), {"ep": (road, a), "last_recv": 0.0, "last_send": 0.0, "session": 0})
            if e not in out:
                out.append(e)
        if p.local and self.loc and self.local_path:  # the device we dial on this computer
            add(self.loc, self.local_path)
        if p.kind == KIND_PLUGIN:  # reachable over the local socket only, on the connection it opened
            return out
        for road, addrs in ((self.udp, p.hints.get("udp")), (self.tcp, p.hints.get("tcp"))):
            if road:
                for a in addrs or []:
                    add(road, a)
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
        self._unhold(now)
        self._reannounce(now)
        for idx, s in list(self.sessions.items()):
            if self.current.get(s.peer) is not s and now - s.last_recv > SESSION_IDLE:
                del self.sessions[idx]
        for idx, h in list(self.hs.items()):
            if now - h["at"] > 60:
                del self.hs[idx]
        for k, inv in list(self.invites.items()):
            if now > inv.exp:
                del self.invites[k]

    def _unhold(self, now: float):
        """Held messages (spec §5): a device's messages wait for its dictionary or its list. That
        must not last: after HOLD_ASK we ask again (its hello, the dictionary); after HOLD_DROP the
        held messages are dropped — the sender resends what matters — and the lists are learnt
        anew."""
        for peer, ps in list(self.peers.items()):
            if not ps.waiting:
                continue
            held = now - ps.wait_since
            if held >= HOLD_DROP:
                k = len(ps.waiting)
                ps.waiting, ps.fetching, ps.asking_info = [], False, False
                ps.dicts, ps.lacks, ps.tried = [], [], []
                self._send_info(peer)  # ours again: the other side re-learns what we have
                if self.on_held:
                    asyncio.get_running_loop().call_soon(self.on_held, peer, k)
            elif held >= HOLD_ASK:
                if not ps.dicts:
                    self._ask_info(peer, ps)
                else:
                    ps.tried = []
                    self._drain(peer, ps)

    def _reannounce(self, now: float):
        """Our addresses changed (another network): tell the devices in session at once with our
        hello, not at the next handshake — they would keep trying the old address until a relay or
        a restart brought them together."""
        if now - self.hints_at < 5:
            return
        self.hints_at = now
        cur = encode(hints_to_wire(self._hints()))
        if self.hints_sent is None or cur == self.hints_sent:
            return  # nothing announced yet, or the same
        for peer in list(self.current):
            self._send_info(peer)

    def _new_index(self) -> int:
        while True:
            i = int.from_bytes(os.urandom(4), "big")
            if i and i not in self.sessions and i not in self.hs:
                return i

    # --- compression (spec §5) ---

    def _push(self, ps: _PeerState, msg: bytes, stream: int = 0, talk: bool = False, reply: bool = False):
        """Queues a message, compressed when worth it: with our dictionary for this device if it
        has it, else the newest one it also has. The slot refers to our list at send time: the
        list changes only through event 0.5, which travels in the same order as messages.
        talk: the message is conversation (not tool 0), so it goes to the history; reply: a result
        or error, dropped if the other device restarts (spec §4.2)."""
        if self.no_compression or _bootstrap(msg):
            ps.st.push(msg, False, stream, reply)
            self._wake()
            return
        d, slot = self.dicts.pick(ps.addr, ps.dicts, ps.lacks)
        z = compress(msg, d, slot)
        if talk:
            self._learn(ps, msg, d, z)
        if z:
            ps.st.push(z, True, stream, reply)
        else:
            ps.st.push(msg, False, stream, reply)
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
        if not ps.waiting:
            ps.wait_since = time.time()
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
                # a sender of an older version compresses its hello too: then we would wait for
                # it forever. Try the dictionaries we have for it — only a hello or a list is taken
                if (plain := self._guess_bootstrap(ps, msg)) is not None:
                    ps.waiting.pop(0)
                    self._message(peer, plain, stream)
                    continue
                self._ask_info(peer, ps)
                return  # wait for a hello or 0.5
            ps.waiting.pop(0)
            if plain is not None:
                self._message(peer, plain, stream)

    def _guess_bootstrap(self, ps, msg: bytes) -> bytes | None:
        """Decompresses a message whose slot is beyond the sender's list we know with each
        dictionary the sender may have used for us (the pair's and the common ones); only a hello
        or a dictionary list is accepted, None — none fits."""
        if len(msg) < 2 or msg[0] == 0:
            return None
        for d in self.dicts.list(ps.addr):
            try:
                plain = decompress(msg, d, MSG_MAX)
                if _bootstrap(plain):
                    decode_array_raw(plain)
                    return plain
            except Exception:
                continue
        return None

    def _ask_info(self, peer, ps):
        """Asks the device for its hello (0.2 info) when we hold its messages without its list:
        it may never send the event again on its own. One at a time; a newer device answers
        uncompressed, an older one — with a slot we may guess (_guess_bootstrap)."""
        if ps.asking_info or time.time() - ps.asked_info < 10:
            return
        ps.asking_info, ps.asked_info = True, time.time()

        async def run():
            try:
                res = await asyncio.wait_for(self.call(peer, 0, 2), 30)
            except Exception:
                res = None
            ps.asking_info = False
            if self.closed or self.peers.get(peer) is not ps or not res or len(res) < 5 or ps.dicts:
                return
            ps.dicts = _ids(decode(res[4]))
            self._fetch_new(peer, ps)
            self._drain(peer, ps)
        asyncio.get_running_loop().create_task(run())

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


def _need_local():
    if not local_supported():
        raise P2PACTError(ERR_FAILED, "the local socket is not supported on Windows yet")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _pair_kind(pp) -> int:
    return pp[5] if len(pp) > 5 and _is_int(pp[5]) else KIND_UNKNOWN


def _ids(v) -> list[bytes]:
    return [x for x in v if isinstance(x, bytes)] if isinstance(v, list) else []


def _bootstrap(m: bytes) -> bool:
    """A hello or a dictionary list ([3, 0, 2|5, …]): they carry what the receiver needs to
    decompress, so they always go uncompressed — a device that restarted (and lost our list) must
    be able to read them."""
    return len(m) > 3 and m[1] == 3 and m[2] == 0 and m[3] in (2, 5)


def _out_of_order(m: bytes) -> bool:
    if len(m) < 2:
        return False
    return m[1] in (1, 2) or (len(m) > 3 and m[1] == 3 and m[2] == 0 and m[3] in (2, 5))
