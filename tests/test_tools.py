"""Named tools (spec §8)."""
import asyncio

import pytest

from p2pact.cbor import decode, encode
from p2pact.node import FIRST_NAMED_TOOL, P2PACTError
from p2pact.store import hints_to_wire
from p2pact.tools import valid_tool_name

from test_kind import eventually
from test_node import echo, make, pair


def test_valid_tool_name():
    for name, want in {"com.example.jira": True, "org.a-b.c1": True, "jira": False, "": False,
                       "Com.example": False, "com..x": False, "p2pact.chat": False, "com.-x": False,
                       "com.x-": False, "com.x\n": False}.items():
        assert valid_tool_name(name) == want, name


def test_named_tools_numbered_per_device(tmp_path):
    """A name gets a number of the device's own, from 64 up, not one a tool already has; the same
    name on another device may have another number, and callers resolve it by name."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")  # both have the echo at 64
        try:
            def reg(n, name):
                num = n.register_tool(name, 3)
                assert num >= FIRST_NAMED_TOOL and num != 64
                assert n.register_tool(name, 3) == num
                n.handle_tool(name, 1, lambda peer, args: [n.name + ":" + name])
            reg(a, "com.acme.one")
            reg(a, "com.acme.two")
            reg(b, "com.acme.two")
            reg(b, "com.acme.one")
            with pytest.raises(ValueError):
                a.register_tool("jira")
            with pytest.raises(ValueError):
                a.register_tool("p2pact.chat")
            await pair(a, b)
            await eventually("hellos", lambda: a.tool_number(b.id.addr, "com.acme.one") is not None
                             and b.tool_number(a.id.addr, "com.acme.one") is not None)
            na, nb = a.tool_number(b.id.addr, "com.acme.one"), b.tool_number(a.id.addr, "com.acme.one")
            assert na != nb  # the numbers differ per device
            assert a.tool_number(b.id.addr, "p2pact.chat") == 1
            for frm, to, name in [(a, b, "com.acme.one"), (a, b, "com.acme.two"), (b, a, "com.acme.one")]:
                res = await asyncio.wait_for(frm.call_tool(to.id.addr, name, 1), 5)
                assert decode(res[0]) == to.name + ":" + name
            assert a.peer_tool_name(b.id.addr, na) == "com.acme.one"
            assert a.tool_name(nb) == "com.acme.one" and a.tool_name(1) == "p2pact.chat" and a.tool_name(64) == ""
            with pytest.raises(P2PACTError):
                await a.call_tool(b.id.addr, "com.acme.none", 1)
            # a tool registered after the session is up reaches the other side at once
            a.register_tool("com.acme.late")
            await eventually("late tool", lambda: b.tool_number(a.id.addr, "com.acme.late") is not None)
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_named_tools_old_hello(tmp_path):
    """A hello without the named map (an older device) names nothing; its numbered tools work as before."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Old")
        try:
            await pair(a, b)
            a._message(b.id.addr, encode([3, 0, 2, "Old", "linux", "old-impl", {64: 1}, [], hints_to_wire({})]))
            assert a.tool_number(b.id.addr, "com.acme.one") is None
            await echo(a, b, b"numbered")
        finally:
            a.close()
            b.close()
    asyncio.run(run())
