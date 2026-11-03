"""Tool 4 `p2pact.plugins` (plugins spec): the plugins a computer hosts. JSON-RPC over `4.1 rpc`.
Install and remove stay on the computer."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from ..grants import LEVEL_READ, LEVEL_WRITE, Grant
from .util import Events, JsonMap, jbool, jint, jobj, jobjs, jstr, jstrs, normalize, wire

if TYPE_CHECKING:
    from .client import Computer

PLUGINS_TOOL = 4


class PluginStatus(str, Enum):
    RUNNING = "running"
    STARTING = "starting"
    RESTARTING = "restarting"
    STOPPED = "stopped"  # switched off
    FAILED = "failed"  # disabled after repeated exits
    UNSUPPORTED = "unsupported"  # not for this system
    BROKEN = "broken"  # unreadable manifest
    UNKNOWN = ""

    @staticmethod
    def of(s: str | None) -> "PluginStatus":
        try:
            return PluginStatus(s or "")
        except ValueError:
            return PluginStatus.UNKNOWN


@dataclass
class PluginInfo:
    name: str
    version: str | None
    title: str | None
    enabled: bool
    status: PluginStatus
    error: str | None
    restarts: int
    pid: int | None
    tools: list[str]  # the tool names the manifest allows
    announced: list[str]  # the tools the plugin has announced now, a subset of `tools`
    needs: list[str]  # `tool[:read|:write]` the plugin asked for
    raw: JsonMap = field(default_factory=dict, repr=False)

    @staticmethod
    def parse(m: JsonMap) -> "PluginInfo":
        return PluginInfo(jstr(m, "name") or "", jstr(m, "version"), jstr(m, "title"), bool(jbool(m, "enabled")),
                          PluginStatus.of(jstr(m, "status")), jstr(m, "error"), jint(m, "restarts") or 0, jint(m, "pid"),
                          jstrs(m, "tools"), jstrs(m, "announced"), jstrs(m, "needs"), m)


@dataclass
class PluginGrants:
    """What a plugin may use of the computer, and which methods of its own tools need only read."""
    name: str
    grants: list[Grant]
    read: dict[str, list[int]]
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class PluginChanged:
    """`plugins/changed`: the plugin as it is now; `removed` — it is gone (the entry is the last one)."""
    plugin: PluginInfo
    removed: bool = False


def _level(v) -> int | None:
    """The engine sends "read"/"write"; an integer level is accepted too."""
    if isinstance(v, bool):
        return None
    if isinstance(v, str):
        return {"read": LEVEL_READ, "write": LEVEL_WRITE}.get(v)
    if isinstance(v, int) and v >= LEVEL_READ:
        return min(v, LEVEL_WRITE)
    return None


async def _quiet(coro):
    try:
        await coro
    except Exception:
        pass


class PluginsClient:
    """Tool 4 `p2pact.plugins` of one computer. enable/disable need write."""

    def __init__(self, computer: "Computer"):
        self._c = computer
        self.events: Events[PluginChanged] = Events()  # of the watch; also after the computer restarted (the watch is repeated)
        self._watching = False
        self._tasks: set[asyncio.Task] = set()

    async def watch(self) -> list[PluginInfo]:
        """`plugins/watch`: subscribes to `events`; gives the plugins as they are now. Repeated
        after the computer's new hello. Needs read."""
        self._watching = True
        try:
            r = await self._call("plugins/watch")
        except Exception:
            self._watching = False
            raise
        return [PluginInfo.parse(m) for m in jobjs(r, "plugins")]

    async def unwatch(self) -> None:
        """`plugins/unwatch`."""
        self._watching = False
        await self._call("plugins/unwatch")

    def _spawn(self, coro):
        t = asyncio.ensure_future(_quiet(coro))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    def _reconnected(self):
        # the device forgot the subscription with its restart (plugins spec §2)
        if self._watching:
            self._spawn(self._call("plugins/watch"))

    def _notified(self, args: list):
        msg = normalize(args[0]) if args else None
        if not isinstance(msg, dict) or msg.get("method") != "plugins/changed":
            return
        p = jobj(msg, "params") or {}
        self.events.emit(PluginChanged(PluginInfo.parse(p), bool(jbool(p, "removed"))))

    async def _call(self, method: str, params: JsonMap | None = None) -> JsonMap:
        return await self._c.rpc(PLUGINS_TOOL, method, params)

    async def list(self) -> list[PluginInfo]:
        """`plugins/list`."""
        return [PluginInfo.parse(m) for m in jobjs(await self._call("plugins/list"), "plugins")]

    async def log(self, name: str, lines: int | None = None) -> str:
        """`plugins/log`: the last `lines` lines of the plugin's log."""
        p: JsonMap = {"name": name}
        if lines is not None:
            p["lines"] = lines
        return jstr(await self._call("plugins/log", p), "log") or ""

    async def grants(self, name: str) -> PluginGrants:
        """`plugins/grants`."""
        r = await self._call("plugins/grants", {"name": name})
        grants = [Grant(g["tool"], lv) for g in jobjs(r, "grants")
                  if isinstance(g.get("tool"), str) and (lv := _level(g.get("level"))) is not None]
        read = {k: [x for x in v if isinstance(x, int)] for k, v in (jobj(r, "read") or {}).items() if isinstance(v, list)}
        return PluginGrants(jstr(r, "name") or name, grants, read, r)

    async def enable(self, name: str) -> None:
        """Starts a plugin (and keeps it on across the computer's restarts). Needs write."""
        await self._call("plugins/enable", {"name": name})

    async def disable(self, name: str) -> None:
        await self._call("plugins/disable", {"name": name})

    async def call_tool(self, name: str, method: int, *args, timeout: float | None = None) -> list:
        """Calls a method of a tool a plugin of the computer serves (core spec §8.2) by the
        tool's name; the number is the computer's own. See Computer.call_tool()."""
        return await self._c.call_tool(name, method, *[wire(a) for a in args], timeout=timeout)
