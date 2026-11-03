"""Tool 4 `p2pact.plugins` (plugins spec): the plugins a computer hosts. JSON-RPC over `4.1 rpc`.
Install and remove stay on the computer."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from ..grants import Grant
from .util import JsonMap, jbool, jint, jobj, jobjs, jstr, jstrs, wire

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


class PluginsClient:
    """Tool 4 `p2pact.plugins` of one computer. enable/disable need write."""

    def __init__(self, computer: "Computer"):
        self._c = computer

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
        grants = [Grant(g["tool"], g["level"]) for g in jobjs(r, "grants")
                  if isinstance(g.get("tool"), str) and isinstance(g.get("level"), int)]
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
