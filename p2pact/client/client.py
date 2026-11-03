"""P2pactClient: an application's side of P2PACT. It pairs with computers (devices running the
P2PACT engine) by their invite, keeps them, and gives the typed clients of their public tools."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..cbor import decode
from ..grants import LEVEL_READ, LEVEL_WRITE, Grant, grant_level
from ..node import ERR_FORBIDDEN, ERR_NO_METHOD, KIND_CLIENT, KIND_PLUGIN, Node, P2PACTError, later
from ..store import Invite, Peer
from .chat import CHAT_TOOL, ChatClient
from .errors import NoMethodError, RpcError, typed
from .fleet import FLEET_TOOL, FleetClient
from .plugins import PLUGINS_TOOL, PluginsClient
from .util import Events, JsonMap, jobj, jstr, normalize, wire

CHAT = "p2pact.chat"
FLEET = "p2pact.fleet"
PLUGINS = "p2pact.plugins"

# What the SDK itself uses, to ask for when pairing: chat and fleet in full, the plugins' view.
# The person of the computer may narrow it (Computer.grants tells what was granted).
DEFAULT_WANTS: list[Grant] = [Grant(CHAT, LEVEL_WRITE), Grant(FLEET, LEVEL_WRITE), Grant(PLUGINS, LEVEL_READ)]


@dataclass
class ClientConfig:
    """How a client reaches computers. `udp` and `tcp` are the addresses it listens on (`""`
    for tcp — only dials; None — no such road)."""
    udp: str | None = "0.0.0.0:0"
    tcp: str | None = ""
    call_timeout: float = 60.0  # how long a call waits for its answer; 0 — for ever. Prompts never time out
    pair_timeout: float = 30.0


class ConnectionState(Enum):
    OFFLINE = "offline"  # no live road to the computer
    ONLINE = "online"  # a session with the computer runs and it has told its tools


# --- events of the client ---

@dataclass
class ComputerEvent:
    computer: "Computer"


@dataclass
class Paired(ComputerEvent):
    """Pairing finished (on our side)."""


@dataclass
class Online(ComputerEvent):
    """The computer's hello came: a session runs, its tools are known. After a restart it comes again."""


@dataclass
class GrantsChanged(ComputerEvent):
    """The computer told what we may use of its tools (event 0.6)."""
    grants: list[Grant]


@dataclass
class Forgotten(ComputerEvent):
    pass


@dataclass
class ToolEvent:
    """An event of a tool the SDK has no typed layer for (a plugin's tool): the numbers are the computer's."""
    computer: "Computer"
    tool: str | None
    tool_number: int
    event: int
    args: list


class P2pactClient:
    """P2pactClient pairs with computers and keeps them. The state (keys, paired computers)
    lives in `dir`; keeping that safe is the application's job.

        async with await P2pactClient.open(data_dir, "My app") as client:
            computer = await client.pair("p2pact1.…")
            chats = await computer.chat.list_sessions()

    Calls are coroutines that raise CallError subclasses (the P2PACT error codes: ForbiddenError…)
    or RpcError (the tool's own errors).
    """

    def __init__(self, node: Node, config: ClientConfig | None = None, owned: bool = False):
        """Use open() or wrap(). `node` is the protocol node, for what this SDK does not wrap: do
        not set its callbacks (unless you wrapped it: see hello())."""
        self.node = node
        self.config = config or ClientConfig()
        self._owned = owned
        self._computers: dict[str, Computer] = {}
        self._sequence: dict[tuple[str, int], int] = {}
        self.computer_events: Events[ComputerEvent] = Events()  # pairing, hellos and grants of computers
        self.tool_events: Events[ToolEvent] = Events()  # events of tools without a typed layer (a plugin's tool)
        # the computer's calls into the chat tool: permissions and questions of agents (chat spec §6, §9.1)
        node.handle(CHAT_TOOL, 1, self._chat_call)
        if owned:
            node.on_paired, node.on_hello, node.on_granted, node.on_event = (
                self.paired, self.hello, self.granted, self.event)

    @classmethod
    async def open(cls, dir: str, name: str, config: ClientConfig | None = None) -> "P2pactClient":
        """Makes the node (keys in `dir`), listens on the configured roads and starts it."""
        config = config or ClientConfig()
        node = Node(str(dir), name)
        node.kind = KIND_CLIENT
        if config.udp is not None:
            await node.listen_udp(config.udp)
        if config.tcp is not None:
            await node.listen_tcp(config.tcp)
        client = cls(node, config, owned=True)
        node.start()
        return client

    @classmethod
    def wrap(cls, node: Node, config: ClientConfig | None = None) -> "P2pactClient":
        """The typed clients over a node the application already runs (it owns the keys, the
        roads, the pairing and the node's callbacks). The SDK only serves the chat tool's calls
        from the computers. The application keeps `on_hello`, `on_event`, `on_granted` and
        `on_paired` of the node and passes them on: hello(), event(), granted(), paired().
        close() leaves the node open."""
        return cls(node, config, owned=False)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.close()

    def close(self):
        if self._owned:
            self.node.close()

    # --- callbacks of the node (for a wrapped node, pass them on) ---

    def hello(self, addr: str):
        """The computer's hello came (the node's `on_hello`)."""
        c = self._computer_or_none(addr)
        if c is not None:
            c._hello_arrived()

    def event(self, addr: str, tool: int, ev: int, raw_args: list):
        """An event of a tool from a computer (the node's `on_event`)."""
        c = self._computer_or_none(addr)
        if c is None:
            return
        args = [decode(a) for a in raw_args]
        if tool == CHAT_TOOL and ev == 1:
            c.chat._notified(args)
        elif tool == FLEET_TOOL and ev == 1:
            c.fleet._notified(args)
        elif tool == PLUGINS_TOOL and ev == 1:
            c.plugins._notified(args)
        elif tool == PLUGINS_TOOL:
            pass
        else:
            self.tool_events.emit(ToolEvent(c, self.node.peer_tool_name(addr, tool) or None, tool, ev,
                                            [normalize(a) for a in args]))

    def granted(self, addr: str, grants: list[Grant]):
        """The computer told what we may use (the node's `on_granted`)."""
        c = self._computer_or_none(addr)
        if c is not None:
            self.computer_events.emit(GrantsChanged(c, grants))

    def paired(self, p: Peer):
        """Pairing finished (the node's `on_paired`)."""
        if _usable(p):
            self.computer_events.emit(Paired(self._computer_of(p.addr)))

    # --- computers ---

    async def pair(self, invite: str, wants: list[Grant] | None = None, timeout: float | None = None) -> "Computer":
        """Pairs with a computer by its invite (`p2pact1.…`, from `nomad invite` or the like) as
        a client application, asking for `wants` (default DEFAULT_WANTS). Completes when the
        pairing is done; the person at the computer may narrow the grants later still:
        GrantsChanged. A bad invite raises ValueError."""
        inv = Invite.parse(invite)
        try:
            p = await self.node.join(inv, timeout or self.config.pair_timeout, DEFAULT_WANTS if wants is None else wants)
        except P2PACTError as e:
            raise typed(e) from None
        return self._computer_of(p.addr)

    def computers(self) -> list["Computer"]:
        """The paired computers."""
        return [self._computer_of(p.addr) for p in self.node.trust.list() if _usable(p)]

    def computer(self, id: str) -> "Computer | None":
        """A paired computer by its address (Computer.id) or None."""
        return self._computer_or_none(id)

    def forget(self, computer: "Computer"):
        """Unpairs a computer: its keys and conversation state go."""
        self.node.forget(computer.id)
        self._computers.pop(computer.id, None)
        self.computer_events.emit(Forgotten(computer))

    # --- internals ---

    def _computer_or_none(self, addr: str) -> "Computer | None":
        c = self._computers.get(addr)
        if c is not None:
            return c
        p = self.node.trust.get(addr)
        return self._computer_of(addr) if p is not None and _usable(p) else None

    def _computer_of(self, addr: str) -> "Computer":
        c = self._computers.get(addr)
        if c is None:
            c = self._computers[addr] = Computer(self, addr)
        return c

    def _chat_call(self, addr: str, args: list):
        c = self._computer_or_none(addr)
        if c is None:
            raise P2PACTError(ERR_FORBIDDEN, "unknown computer")
        return later(c.chat._incoming([decode(a) for a in args]))

    def _next_event_number(self, addr: str, stream: int) -> int:
        """The number of our next notification on a stream: from 1 for each pair of devices and stream (fleet spec §1)."""
        n = self._sequence[addr, stream] = self._sequence.get((addr, stream), 0) + 1
        return n

    def _reset_event_numbers(self, addr: str):
        for k in [k for k in self._sequence if k[0] == addr]:
            del self._sequence[k]


def _usable(p: Peer) -> bool:
    return p.kind not in (KIND_PLUGIN, KIND_CLIENT)


class Computer:
    """A paired computer: the device that runs agents. The typed clients of its tools hang off
    it: `chat`, `fleet`, `plugins`."""

    def __init__(self, owner: P2pactClient, id: str):
        self.owner = owner
        self.id = id
        self._ready = asyncio.Event()
        self._hello = False
        self.chat = ChatClient(self)
        self.fleet = FleetClient(self)
        self.plugins = PluginsClient(self)

    @property
    def _node(self) -> Node:
        return self.owner.node

    @property
    def name(self) -> str:
        p = self._node.trust.get(self.id)
        return p.name if p else ""

    @property
    def os(self) -> str | None:
        p = self._node.trust.get(self.id)
        return p.os if p else None

    @property
    def state(self) -> ConnectionState:
        """ONLINE when a session with the computer runs and it has told its tools."""
        return ConnectionState.ONLINE if self._hello and self._node.paths(self.id) else ConnectionState.OFFLINE

    @property
    def paths(self) -> list[str]:
        """The roads in use: `udp`, `tcp`, `relay:<address>`…"""
        return self._node.paths(self.id)

    @property
    def grants(self) -> list[Grant]:
        """What the computer lets us use of its tools, as it told us (event 0.6). Paired with wants (the SDK
        always asks): nothing until the first 0.6 arrives. A device that joined without wants has everything
        until told."""
        return self._node.granted_by(self.id)

    def level(self, tool: str) -> int:
        """The level we have on a tool of the computer: 0 none, 1 LEVEL_READ, 2 LEVEL_WRITE."""
        return grant_level(self.grants, tool)

    def can_read(self, tool: str) -> bool:
        return self.level(tool) >= LEVEL_READ

    def can_write(self, tool: str) -> bool:
        return self.level(tool) >= LEVEL_WRITE

    async def when_online(self, timeout: float | None = None) -> "Computer":
        """Completes when the computer's hello has come (at once, if it has)."""
        await asyncio.wait_for(self._ready.wait(), timeout)
        return self

    def _hello_arrived(self):
        self._hello = True
        self.owner._reset_event_numbers(self.id)
        self.chat._reconnected()
        self.fleet._reconnected()
        self.plugins._reconnected()
        self._ready.set()
        self.owner.computer_events.emit(Online(self))

    async def rpc(self, tool: int, method: str, params: JsonMap | None, stream: int = 0,
                  timeout: float | None = None) -> JsonMap:
        """A JSON-RPC call over the tool's `rpc` method (chat spec §2): the result object, or the
        tool's error. `timeout` seconds (None — the config's, 0 — for ever)."""
        req: JsonMap = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            req["params"] = params
        t = self.owner.config.call_timeout if timeout is None else timeout
        try:
            r = await asyncio.wait_for(self._node.call_on(self.id, stream, tool, 1, wire(req)), t or None)
        except P2PACTError as e:
            raise typed(e) from None
        msg = normalize(decode(r[0])) if r else None
        if not isinstance(msg, dict):
            from .errors import FailedError
            raise FailedError(5, "empty response")
        err = jobj(msg, "error")
        if err is not None:
            code = err.get("code")
            raise RpcError(code if isinstance(code, int) else RpcError.FAILED, jstr(err, "message") or "", err.get("data"))
        return jobj(msg, "result") or {}

    def notify(self, tool: int, method: str, params: JsonMap, stream: int):
        """Sends a JSON-RPC notification as the tool's `notify` event."""
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        self._node.event_on(self.id, stream, tool, 1, wire(msg), self.owner._next_event_number(self.id, stream))

    def tool_number(self, name: str) -> int | None:
        """The number the computer gave a tool of its own (a plugin's) in its hello; None until it is known."""
        return self._node.tool_number(self.id, name)

    async def call_tool(self, name: str, method: int, *args: Any, timeout: float | None = None) -> list:
        """Calls a method of a tool by name; the number is the computer's own (hosted tools,
        core spec §8.2). It waits for the computer's hello if it has not come. Arguments are JSON
        trees (numbers, text, lists, maps, bytes); the result values are decoded the same way."""
        t = self.owner.config.call_timeout if timeout is None else timeout
        if self.tool_number(name) is None and not self._hello:
            # the hello may still be on its way after pairing
            try:
                await asyncio.wait_for(self._ready.wait(), t or 10)
            except asyncio.TimeoutError:
                pass
        n = self.tool_number(name)
        if n is None:
            raise NoMethodError(ERR_NO_METHOD, f"the computer has no tool {name}")
        try:
            r = await asyncio.wait_for(self._node.call_on(self.id, 0, n, method, *args), t or None)
        except P2PACTError as e:
            raise typed(e) from None
        return [decode(x) for x in r]
