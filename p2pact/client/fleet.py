"""Tool 2 `p2pact.fleet` (fleet spec): the computer and its agent sessions. JSON-RPC over `2.1 rpc`."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from .models import AgentInfo
from .util import Events, JsonMap, jbool, jint, jobj, jobjs, jstr, normalize, stream_of

if TYPE_CHECKING:
    from .client import Computer

FLEET_TOOL = 2


@dataclass
class FleetNode:
    """The computer as the fleet describes it (`Node`)."""
    id: str
    name: str
    os: str | None
    status: JsonMap  # online, lid, battery, temperature, working… as the computer reports
    agents: list[AgentInfo]
    capabilities: JsonMap
    raw: JsonMap = field(default_factory=dict, repr=False)

    @staticmethod
    def parse(m: JsonMap) -> "FleetNode":
        caps = jobj(m, "capabilities") or {}
        return FleetNode(jstr(m, "id") or "", jstr(m, "name") or "", jstr(m, "os"), jobj(m, "status") or {},
                         [AgentInfo.parse(a) for a in jobjs(caps, "agents")], caps, m)


@dataclass
class FleetHello:
    protocol: str | None
    node: FleetNode
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class FleetSession:
    """An agent session of the fleet (`Session`): the same id as the chat's."""
    id: str
    agent: str | None
    model: str | None
    dir: str | None
    keep: bool | None
    perms: str | None
    phase: str | None  # starting, working, waiting, idle… as the computer says
    title: str | None
    updated: str | None  # RFC 3339
    ask: object  # the `ask` of the status, if the agent waits for the person
    raw: JsonMap = field(default_factory=dict, repr=False)

    @staticmethod
    def parse(m: JsonMap) -> "FleetSession":
        spec, st = jobj(m, "spec") or {}, jobj(m, "status") or {}
        return FleetSession(jstr(m, "id") or "", jstr(spec, "agent"), jstr(spec, "model"), jstr(spec, "dir"),
                            jbool(spec, "keep"), jstr(spec, "perms"), jstr(st, "phase"), jstr(st, "title"),
                            jstr(st, "updated"), st.get("ask"), m)


@dataclass
class SessionSpec:
    """What `session/create` starts. `extra` is added as it is, for fields this SDK does not know."""
    agent: str | None = None
    dir: str | None = None
    model: str | None = None
    keep: bool | None = None
    perms: str | None = None
    extra: JsonMap = field(default_factory=dict)

    def to_map(self) -> JsonMap:
        m = {k: v for k, v in (("agent", self.agent), ("dir", self.dir), ("model", self.model), ("keep", self.keep),
                               ("perms", self.perms)) if v is not None}
        m.update(self.extra)
        return m


@dataclass
class FleetMessage:
    seq: int
    role: str
    text: str
    time: str | None
    raw: JsonMap = field(default_factory=dict, repr=False)

    @staticmethod
    def parse(m: JsonMap) -> "FleetMessage":
        return FleetMessage(jint(m, "seq") or 0, jstr(m, "role") or "", jstr(m, "text") or "", jstr(m, "time"), m)


@dataclass
class FleetMessages:
    """`session/messages`: the replies after a number; `older` — there are earlier ones."""
    messages: list[FleetMessage]
    last: int | None
    older: bool
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class CloseResult:
    ok: bool
    warning: str | None  # done, but not smoothly
    raw: JsonMap = field(default_factory=dict, repr=False)


# --- events of a watch (fleet spec §4) ---

@dataclass
class FleetEvent:
    """Base of the events of a watch."""


@dataclass
class SessionsChanged(FleetEvent):
    """The whole list, at every change."""
    sessions: list[FleetSession]


@dataclass
class SessionMessages(FleetEvent):
    """New replies of a session."""
    id: str
    messages: list[FleetMessage]


@dataclass
class Resync(FleetEvent):
    """Replies of `id` were lost: read messages(id, after) again."""
    id: str


@dataclass
class Partial(FleetEvent):
    """The agent's text while it is written (only if the watch asked for `partial`)."""
    id: str
    message: JsonMap


@dataclass
class Notify(FleetEvent):
    """What the computer would show as a notification."""
    text: str


@dataclass
class OtherEvent(FleetEvent):
    method: str
    params: JsonMap


class FleetWatch:
    """An active watch: `sessions` at the start; close() (or `await watch.stop()`) unsubscribes."""

    def __init__(self, sessions: list[FleetSession], on_close: Callable[[], None]):
        self.sessions = sessions
        self._on_close = on_close

    def close(self):
        self._on_close()


class FleetClient:
    """Tool 2 `p2pact.fleet` of one computer. Write methods need level 2."""

    def __init__(self, computer: "Computer"):
        self._c = computer
        self.events: Events[FleetEvent] = Events()  # of the watch; also after the computer restarted (the watch is repeated)
        self._watching: bool | None = None  # partial, or None — not watching
        self._tasks: set[asyncio.Task] = set()

    async def _call(self, method: str, params: JsonMap | None = None, timeout: float | None = None) -> JsonMap:
        return await self._c.rpc(FLEET_TOOL, method, params, stream_of(jstr(params or {}, "id")), timeout)

    async def _write(self, method: str, params: JsonMap) -> JsonMap:
        # the methods that change a session may take minutes: no timeout (fleet spec §1)
        return await self._call(method, params, timeout=0)

    # --- read ---

    async def hello(self) -> FleetHello:
        r = await self._call("fleet/hello")
        return FleetHello(jstr(r, "protocol"), FleetNode.parse(jobj(r, "node") or {}), r)

    async def node(self) -> FleetNode:
        return FleetNode.parse(await self._call("node/get"))

    async def sessions(self) -> list[FleetSession]:
        return [FleetSession.parse(m) for m in jobjs(await self._call("session/list"), "sessions")]

    async def session(self, id: str) -> FleetSession:
        """`session/get`; no such session — RpcError -32004."""
        return FleetSession.parse(await self._call("session/get", {"id": id}))

    async def messages(self, id: str, after: int | None = None, limit: int | None = None) -> FleetMessages:
        """`session/messages`: the replies after number `after` (without it, the last `limit`)."""
        p: JsonMap = {"id": id}
        if after is not None:
            p["after"] = after
        if limit is not None:
            p["limit"] = limit
        r = await self._call("session/messages", p)
        return FleetMessages([FleetMessage.parse(m) for m in jobjs(r, "messages")], jint(r, "last"),
                             bool(jbool(r, "older")), r)

    async def watch(self, partial: bool = False) -> FleetWatch:
        """Subscribes to the fleet: `events` get the changes. Close the result to stop. With
        `partial` the agent's text comes while it is written."""
        self._watching = partial
        r = await self._call("fleet/watch", {"partial": partial})

        def stop():
            self._watching = None
            self._spawn(self._call("fleet/unwatch"))
        return FleetWatch([FleetSession.parse(m) for m in jobjs(r, "sessions")], stop)

    # --- write ---

    async def create(self, spec: SessionSpec, text: str | None = None) -> FleetSession:
        p: JsonMap = {"spec": spec.to_map()}
        if text is not None:
            p["text"] = text
        return FleetSession.parse(await self._write("session/create", p))

    async def send(self, id: str, text: str) -> None:
        """Puts a message into the session."""
        await self._write("session/send", {"id": id, "text": text})

    async def answer(self, id: str, wait_id: str | None = None, answers: dict[str, str] | None = None,
                     allow: bool | None = None) -> None:
        """Answers an agent's question (`answers`: question → label) or permission (`allow`)."""
        p: JsonMap = {"id": id}
        if wait_id is not None:
            p["waitId"] = wait_id
        if answers is not None:
            p["answers"] = answers
        if allow is not None:
            p["allow"] = allow
        await self._write("session/answer", p)

    async def interrupt(self, id: str) -> None:
        await self._write("session/interrupt", {"id": id})

    async def close(self, id: str) -> CloseResult:
        r = await self._write("session/close", {"id": id})
        ok = jbool(r, "ok")
        return CloseResult(True if ok is None else ok, jstr(r, "warning"), r)

    async def set_keep(self, id: str, on: bool) -> None:
        """Keeps the agent running (on) or lets it stop."""
        await self._write("session/setKeep", {"id": id, "on": on})

    async def status(self) -> JsonMap:
        """The engine's state: version, mode, link, clients, peers (write: it names the device's data directory)."""
        return await self._call("engine/status")

    async def settings(self) -> JsonMap:
        return await self._call("settings/get")

    async def set_settings(self, patch: JsonMap) -> JsonMap:
        """Changes settings and gives them as they are after; invalid `patch` — RpcError -32602."""
        return await self._call("settings/set", {"patch": patch})

    async def request(self, method: str, params: JsonMap | None = None) -> JsonMap:
        """Any other method of the fleet."""
        return await self._call(method, params)

    # --- events ---

    def _spawn(self, coro):
        t = asyncio.ensure_future(_quiet(coro))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    def _reconnected(self):
        # the device forgot the subscription with its restart (fleet spec §4)
        if self._watching is not None:
            self._spawn(self._call("fleet/watch", {"partial": self._watching}))

    def _notified(self, args: list):
        msg = normalize(args[0]) if args else None
        if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
            return
        method, p = msg["method"], jobj(msg, "params") or {}
        if method == "session/changed":
            ev: FleetEvent = SessionsChanged([FleetSession.parse(m) for m in jobjs(p, "sessions")])
        elif method == "session/messages":
            ev = SessionMessages(jstr(p, "id") or "", [FleetMessage.parse(m) for m in jobjs(p, "messages")])
        elif method == "session/resync":
            ev = Resync(jstr(p, "id") or "")
        elif method == "session/partial":
            ev = Partial(jstr(p, "id") or "", jobj(p, "message") or {})
        elif method == "notify":
            ev = Notify(jstr(p, "text") or "")
        else:
            ev = OtherEvent(method, p)
        self.events.emit(ev)


async def _quiet(coro):
    try:
        await coro
    except Exception:
        pass
