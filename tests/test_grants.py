"""Grants per trusted device (spec §8.1): calls outside them are error 4, read methods,
level-checking handlers, events only with read, method and event 0.6."""
import asyncio
import json
import os

import pytest

from p2pact.cbor import decode
from p2pact.grants import (ALL_TOOLS, LEVEL_READ, LEVEL_WRITE, Grant, default_grants, grant_level, parse_grants)
from p2pact.node import ERR_FORBIDDEN, P2PACTError
from p2pact.store import Trust

from test_kind import eventually
from test_node import echo, make, pair


async def code(coro) -> int:
    try:
        await asyncio.wait_for(coro, 5)
    except P2PACTError as e:
        return e.code
    return 0


def test_grant_level():
    g = [Grant("com.a.x", LEVEL_READ), Grant("com.a.y", LEVEL_WRITE)]
    for tool, want in {"com.a.x": 1, "com.a.y": 2, "com.a.z": 0, "": 0}.items():
        assert grant_level(g, tool) == want, tool
    assert grant_level(None, "any") == LEVEL_WRITE and grant_level([], "any") == 0  # None is the default
    assert grant_level([Grant(ALL_TOOLS, LEVEL_READ), Grant("com.a.x", LEVEL_WRITE)], "com.a.x") == LEVEL_WRITE
    assert parse_grants([["a.b", 1], ["c.d", 9], ["bad"], ["e.f", 0], "x"]) == [Grant("a.b", 1), Grant("c.d", 2)]
    assert parse_grants("nope") is None


def test_grants_default(tmp_path):
    """Devices whose grants were never set (every device paired before grants) use everything."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")
        try:
            await pair(a, b)
            assert a.grants(b.id.addr) == default_grants()
            await echo(b, a, b"as before")
            # a trust file from before grants has no such field
            path = os.path.join(a.dir, "net-peers.json")
            peers = json.load(open(path))
            assert peers[0]["grants"] is None  # the Go implementation writes null too
            for p in peers:
                p.pop("grants", None)
                p.pop("granted", None)
            json.dump(peers, open(path, "w"))
            p = Trust(a.dir).get(b.id.addr)
            assert p is not None and p.grants is None and p.allowed() == default_grants()
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_grants_persist(tmp_path):
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")
        try:
            await pair(a, b)
            want = [Grant("com.a.x", LEVEL_READ)]
            a.set_grants(b.id.addr, want)
            assert Trust(a.dir).get(b.id.addr).allowed() == want
            a.revoke_grants(b.id.addr)
            p = Trust(a.dir).get(b.id.addr)
            assert p.grants == [] and p.allowed() == []  # revoked grants do not come back as the default
            with pytest.raises(P2PACTError):
                a.set_grants("nobody", want)
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_grants_enforced(tmp_path):
    """A call outside the grants is error 4; read methods need read, the rest write; tool 0 is always allowed."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")
        try:
            ok = lambda peer, args: ["ok"]
            a.handle_tool("com.acme.notes", 1, ok)  # write
            a.handle_tool("com.acme.notes", 2, ok)  # read
            a.handle_tool("com.acme.mail", 1, ok)
            a.mark_read(a.register_tool("com.acme.notes"), 2)
            await pair(a, b)
            addr, me = a.id.addr, b.id.addr
            call = lambda tool, method: code(b.call_tool(addr, tool, method))
            await eventually("hello", lambda: b.tool_number(addr, "com.acme.notes") is not None)
            assert await call("com.acme.notes", 1) == 0 and await call("com.acme.mail", 1) == 0  # the default allows everything
            a.set_grants(me, [Grant("com.acme.notes", LEVEL_READ)])
            assert await call("com.acme.notes", 2) == 0  # read method at read
            assert await call("com.acme.notes", 1) == ERR_FORBIDDEN  # write method at read
            assert await call("com.acme.mail", 1) == ERR_FORBIDDEN  # a tool outside the grants
            assert await code(b.call(addr, 64, 1, b"x")) == ERR_FORBIDDEN  # the echo has no name: not covered without "*"
            await asyncio.wait_for(b.call(addr, 0, 1), 5)  # ping
            a.grant(me, "com.acme.notes", LEVEL_WRITE)
            assert await call("com.acme.notes", 1) == 0  # write after widening
            a.revoke_grants(me)
            assert await call("com.acme.notes", 2) == ERR_FORBIDDEN
            a.set_grants(me, [Grant(ALL_TOOLS, LEVEL_READ)])
            assert await call("com.acme.mail", 1) == ERR_FORBIDDEN and await call("com.acme.notes", 2) == 0
            a.grant(me, ALL_TOOLS, 0)  # level 0 removes the entry
            assert a.grants(me) == []
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_grants_level_handler(tmp_path):
    """A tool whose one method carries many checks the level itself."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")
        try:
            def h(peer, level, args):
                m = decode(args[0])
                if m != "session/list" and level < LEVEL_WRITE:
                    raise P2PACTError(ERR_FORBIDDEN, "read only")
                return [m]
            a.handle_level(1, 1, h)
            await pair(a, b)
            assert a._info(b.id.addr)[3].get(1) == 1  # a tool with a level handler is in the hello
            addr, me = a.id.addr, b.id.addr
            a.set_grants(me, [Grant("p2pact.chat", LEVEL_READ)])
            assert await code(b.call(addr, 1, 1, "session/list")) == 0
            assert await code(b.call(addr, 1, 1, "session/prompt")) == ERR_FORBIDDEN
            a.set_grants(me, [Grant("p2pact.chat", LEVEL_WRITE)])
            assert await code(b.call(addr, 1, 1, "session/prompt")) == 0
            a.set_grants(me, [])
            assert await code(b.call(addr, 1, 1, "session/list")) == ERR_FORBIDDEN
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_grants_events_and_tell(tmp_path):
    """Events of a tool go only to devices with at least read on it; the device is told its grants (0.6)."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")
        try:
            events, told = [], []
            b.on_event = lambda peer, tool, ev, args: events.append(decode(args[0]))
            b.on_granted = lambda peer, g: told.append(g)
            num = a.register_tool("com.acme.feed")
            await pair(a, b)
            addr, me = a.id.addr, b.id.addr
            a.event(me, num, 1, "everyone")
            await eventually("event", lambda: events == ["everyone"])
            a.set_grants(me, [Grant("com.acme.other", LEVEL_WRITE)])
            await eventually("event 0.6", lambda: told == [[Grant("com.acme.other", LEVEL_WRITE)]])
            assert b.granted_by(addr) == [Grant("com.acme.other", LEVEL_WRITE)]
            a.event(me, num, 1, "hidden")  # no read: not sent
            await asyncio.sleep(0.3)
            a.grant(me, "com.acme.feed", LEVEL_READ)
            a.event(me, num, 1, "visible")
            await eventually("visible", lambda: events == ["everyone", "visible"])  # "hidden" never came
            # method 0.6: what the caller may use
            res = await asyncio.wait_for(b.call(addr, 0, 6), 5)
            assert parse_grants(decode(res[0])) == [Grant("com.acme.other", LEVEL_WRITE), Grant("com.acme.feed", LEVEL_READ)]
        finally:
            a.close()
            b.close()
    asyncio.run(run())
