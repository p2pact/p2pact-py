"""p2pact.client: the plugins tool and hosted tools against a fake computer."""
import pytest

from p2pact.client import DEFAULT_WANTS, ForbiddenError, NoMethodError, PluginChanged, PluginStatus, RpcError
from p2pact.grants import LEVEL_READ, LEVEL_WRITE, Grant

from client_support import Rig, assert_sent, fixture

WANTS = DEFAULT_WANTS + [Grant("com.example.hello", LEVEL_WRITE)]


async def test_list_log_grants(tmp_path):
    async with Rig(tmp_path) as rig:
        plugins = (await rig.connect(WANTS)).plugins
        (p,) = await plugins.list()
        assert (p.name, p.status, p.enabled, p.pid) == ("com.example.hello", PluginStatus.RUNNING, True, 4242)
        assert p.announced == ["com.example.hello"] and p.needs == ["p2pact.chat:read"]

        assert await plugins.log("com.example.hello", 2) == "started\nready\n"
        assert_sent(rig.engine, 4, "plugins/log", "p2pact.plugins", "plugins.log.request")

        g = await plugins.grants("com.example.hello")
        assert g.grants == [Grant("p2pact.chat", LEVEL_READ)]
        assert g.read == {"com.example.hello": [2]}

        # plugins are asked for with read only: writing needs the person to widen it
        with pytest.raises(ForbiddenError):
            await plugins.enable("com.example.hello")


async def test_enable_disable_with_write(tmp_path):
    async with Rig(tmp_path) as rig:
        computer = await rig.connect(WANTS + [Grant("p2pact.plugins", LEVEL_WRITE)])
        await computer.plugins.enable("com.example.hello")
        assert_sent(rig.engine, 4, "plugins/enable", "p2pact.plugins", "plugins.enable.request")
        await computer.plugins.disable("com.example.hello")
        assert_sent(rig.engine, 4, "plugins/disable", "p2pact.plugins", "plugins.disable.request")


async def test_calls_plugin_tool_by_name(tmp_path):
    async with Rig(tmp_path) as rig:
        computer = await rig.connect(WANTS)
        n = computer.tool_number("com.example.hello")
        assert n is not None and n >= 64  # a number from 64 up, the computer's own
        assert await computer.plugins.call_tool("com.example.hello", 1, "world") == ["hello world"]
        # a tool the computer does not announce
        with pytest.raises(NoMethodError):
            await computer.plugins.call_tool("com.example.nothing", 1)


async def test_tool_grant_is_needed(tmp_path):
    async with Rig(tmp_path) as rig:
        computer = await rig.connect()  # no grant on the hosted tool
        with pytest.raises(ForbiddenError):
            await computer.call_tool("com.example.hello", 1, "x")


async def test_grants_level_int_is_accepted(tmp_path):
    async with Rig(tmp_path) as rig:
        plugins = (await rig.connect(WANTS)).plugins
        rig.engine.overrides["4:plugins/grants"] = lambda p: {"jsonrpc": "2.0", "result": {
            "name": "x", "grants": [{"tool": "a", "level": 2}, {"tool": "b", "level": "write"},
                                    {"tool": "c", "level": "nope"}], "read": {}}}
        g = await plugins.grants("x")
        assert g.grants == [Grant("a", LEVEL_WRITE), Grant("b", LEVEL_WRITE)]


async def test_unknown_plugin_log_is_an_error(tmp_path):
    async with Rig(tmp_path) as rig:
        plugins = (await rig.connect(WANTS)).plugins
        with pytest.raises(RpcError) as e:
            await plugins.log("com.example.nope")
        assert e.value.code == -32004


async def test_watch_delivers_changed_and_unwatch(tmp_path):
    async with Rig(tmp_path) as rig:
        plugins = (await rig.connect(WANTS)).plugins
        events = plugins.events.stream()
        (p,) = await plugins.watch()
        assert p.name == "com.example.hello"
        assert_sent(rig.engine, 4, "plugins/watch", "p2pact.plugins", "plugins.watch.request")

        rig.engine.notify(4, fixture("p2pact.plugins", "plugins.changed.notification"))
        rig.engine.notify(4, fixture("p2pact.plugins", "plugins.changed.removed.notification"))
        ev = await events.next(10)
        assert isinstance(ev, PluginChanged) and not ev.removed
        assert (ev.plugin.name, ev.plugin.status, ev.plugin.pid) == ("com.example.hello", PluginStatus.RUNNING, 4242)
        ev = await events.next(10)
        assert ev.removed and ev.plugin.status == PluginStatus.STOPPED

        await plugins.unwatch()
        assert_sent(rig.engine, 4, "plugins/unwatch", "p2pact.plugins", "plugins.unwatch.request")
