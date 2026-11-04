"""Tool 5 p2pact.term (spec term.md) and Former names (core spec §8.1): a tool of the spec served by
the application, an alias (a former name) sharing grants, the number or the former name to call by."""
import asyncio

import pytest

from p2pact.cbor import decode
from p2pact.grants import LEVEL_READ, LEVEL_WRITE, Grant
from p2pact.node import ERR_FORBIDDEN, ERR_NO_METHOD, P2PACTError
from p2pact.tools import FIRST_NAMED_TOOL, fixed_tool

from test_grants import code
from test_kind import eventually
from test_node import make, pair

TERM = "p2pact.term"
FORMER = "com.example.term"


def answers(who):
    return lambda peer, level, method, args: [who]


def read_or_write(name):
    def h(peer, level, method, args):
        if method != 1 and level < LEVEL_WRITE:
            raise P2PACTError(ERR_FORBIDDEN, "read only")
        return [name]
    return h


async def text(coro) -> str:
    return decode((await asyncio.wait_for(coro, 5))[0])


def test_fixed_tool_served_by_app(tmp_path):
    """p2pact.term has the fixed number 5, is announced in {tool: version}, the node checks read and
    the handler the rest; it leaves the hello when taken back."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")
        try:
            assert fixed_tool(TERM) == 5 and fixed_tool("com.example.x") is None
            with pytest.raises(ValueError):
                a.register_tool(TERM)  # a name of the spec is not a named tool
            await pair(a, b)
            addr, me = a.id.addr, b.id.addr
            a.handle_tool_all(TERM, read_or_write(TERM))
            await eventually("term in the hello", lambda: b.peer_has_tool(addr, TERM))
            assert b.peer_tools(addr) == []  # not in the named map
            assert b.resolve_tool(addr, TERM) == (5, TERM)
            call = lambda m: code(b.call_tool(addr, TERM, m))
            assert await call(1) == 0  # default grants: write
            a.set_grants(me, [Grant(TERM, LEVEL_READ)])
            assert await call(1) == 0
            assert await call(2) == ERR_FORBIDDEN  # write at read
            a.set_grants(me, [Grant("p2pact.chat", LEVEL_WRITE)])
            assert await call(1) == ERR_FORBIDDEN  # no grant on term
            a.unregister_tool(TERM)
            await eventually("gone from the hello", lambda: not b.peer_has_tool(addr, TERM))
            assert not a.tool_handlers
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_alias_validation(tmp_path):
    async def run():
        a = await make(tmp_path, "Mac")
        try:
            with pytest.raises(ValueError):
                a.alias_tool("p2pact.chat", TERM)  # a name of the spec is not an alias
            with pytest.raises(ValueError):
                a.alias_tool(FORMER, FORMER)
            with pytest.raises(ValueError):
                a.alias_tool(FORMER, "jira")
            a.alias_tool(FORMER, TERM)
            a.alias_tool("com.example.shell", FORMER)  # an alias of an alias names the same tool
            assert a._tool_names(TERM)[0] == TERM and set(a._tool_names("com.example.shell")) == {
                TERM, FORMER, "com.example.shell"}
        finally:
            a.close()
    asyncio.run(run())


def test_alias_rights(tmp_path):
    """Grants on either name count for both (the highest wins), for calls and for events; read does
    not give write; each name answers under the number it was called by."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")
        try:
            a.alias_tool(FORMER, TERM)
            a.handle_tool_all(TERM, read_or_write(TERM))
            a.handle_tool_all(FORMER, read_or_write(FORMER))
            events = []
            b.on_event = lambda peer, tool, ev, args: events.append(tool)
            await pair(a, b)
            addr, me = a.id.addr, b.id.addr
            await eventually("both names", lambda: b.peer_has_tool(addr, TERM) and b.peer_has_tool(addr, FORMER))
            alias = b.tool_number(addr, FORMER)
            assert alias >= FIRST_NAMED_TOOL
            cases = [
                ([Grant(FORMER, LEVEL_WRITE)], LEVEL_WRITE),
                ([Grant(TERM, LEVEL_WRITE)], LEVEL_WRITE),
                ([Grant(TERM, LEVEL_READ), Grant(FORMER, LEVEL_WRITE)], LEVEL_WRITE),
                ([Grant(FORMER, LEVEL_READ)], LEVEL_READ),
                ([Grant(TERM, LEVEL_READ)], LEVEL_READ),
                ([Grant("p2pact.chat", LEVEL_WRITE)], 0),
            ]
            for grants, level in cases:
                a.set_grants(me, grants)
                events.clear()
                for name in (TERM, FORMER):
                    assert a.level(me, name) == level, (grants, name)
                    assert (await code(b.call_tool(addr, name, 1)) == 0) == (level >= LEVEL_READ), (grants, name)
                    assert (await code(b.call_tool(addr, name, 2)) == 0) == (level >= LEVEL_WRITE), (grants, name)
                    if level:
                        assert await text(b.call_tool(addr, name, 1)) == name  # answers under the name called by
                # events of either number reach a device with read on either name
                a.event(me, 5, 3)
                a.event(me, alias, 3)
                await asyncio.sleep(0.3)
                assert events == ([5, alias] if level >= LEVEL_READ else []), (grants, events)
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_alias_old_and_new_devices(tmp_path):
    """A device that knows the terminal only by its former name and one that serves p2pact.term talk
    both ways: a new caller reaches the old device by the former name, the new one by 5; an old
    caller reaches the new device by the former name."""
    async def run():
        old, new, phone = await make(tmp_path, "Old"), await make(tmp_path, "New"), await make(tmp_path, "Phone")
        try:
            old.handle_tool_all(FORMER, answers("old"))
            new.alias_tool(FORMER, TERM)
            new.handle_tool_all(TERM, answers("new:5"))
            new.handle_tool_all(FORMER, answers("new:alias"))
            phone.alias_tool(FORMER, TERM)  # a new caller
            await pair(new, old)
            await pair(phone, old)
            await pair(phone, new)
            o, n, p = old.id.addr, new.id.addr, phone.id.addr
            await eventually("hellos", lambda: phone.peer_has_tool(o, FORMER) and phone.peer_has_tool(n, TERM)
                             and old.peer_has_tool(n, FORMER) and new.peer_has_tool(o, FORMER))
            assert not phone.peer_has_tool(o, TERM)  # the old device does not announce 5
            num, called = phone.resolve_tool(o, TERM)
            assert num >= FIRST_NAMED_TOOL and called == FORMER
            assert phone.resolve_tool(n, TERM) == (5, TERM)
            num, called = phone.resolve_tool(n, FORMER)  # asked by the former name itself
            assert num >= FIRST_NAMED_TOOL and called == FORMER
            new.set_grants(o, [Grant(TERM, LEVEL_WRITE)])  # an old caller, granted the new name
            for frm, to, name, want in [(phone, o, TERM, "old"), (phone, n, TERM, "new:5"),
                                        (new, o, TERM, "old"), (old, n, FORMER, "new:alias")]:
                assert await text(frm.call_tool(to, name, 1)) == want, (frm.name, name)
            assert await code(old.call_tool(p, "com.example.none", 1)) == ERR_NO_METHOD
            assert await code(phone.call_tool(n, "com.example.none", 1)) == ERR_NO_METHOD
        finally:
            old.close()
            new.close()
            phone.close()
    asyncio.run(run())
