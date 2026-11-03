"""Wants at pairing (spec §2): the newcomer asks, the inviting application narrows or refuses."""
import asyncio

from p2pact.grants import ALL_TOOLS, LEVEL_READ, LEVEL_WRITE, Grant, default_grants
from p2pact.node import ERR_FORBIDDEN, KIND_CLIENT
from p2pact.store import Invite

from test_grants import code
from test_kind import eventually
from test_node import echo, make, pair


async def join_wants(inviter, joiner, wants):
    await joiner.join(Invite.parse(str(inviter.invite(600))), 10, wants)


def test_wants_asked_are_granted(tmp_path):
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "App")
        try:
            b.kind = KIND_CLIENT
            want = [Grant("com.acme.x", LEVEL_READ), Grant("p2pact.chat", LEVEL_WRITE)]
            await join_wants(a, b, want)
            await eventually("the inviter remembers the joiner", lambda: a.trust.get(b.id.addr))
            p = a.trust.get(b.id.addr)
            assert p.allowed() == want and p.kind == KIND_CLIENT
            await eventually("the newcomer is told", lambda: b.granted_by(a.id.addr) == want)
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_wants_none_is_everything(tmp_path):
    """Pairing without wants asks for everything: behaviour as before, and no event 0.6 is needed."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")
        try:
            await pair(a, b)
            p = a.trust.get(b.id.addr)
            assert p.grants is None and p.allowed() == default_grants()
            await echo(b, a, b"x")
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_wants_decided_by_application(tmp_path):
    """The inviting application sees the wants and decides what is granted before it accepts."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "App")
        try:
            asked, paired = [], []
            release = asyncio.Event()

            async def on_wants(p, wants):
                asked.append((p, wants))
                await release.wait()
                return [Grant("com.acme.x", LEVEL_READ)], True
            a.on_wants = on_wants
            a.on_paired = paired.append
            b.kind = KIND_CLIENT
            await join_wants(a, b, [Grant(ALL_TOOLS, LEVEL_WRITE)])
            await eventually("asked", lambda: asked)
            p, wants = asked[0]
            assert p.name == "App" and p.kind == KIND_CLIENT and wants == [Grant(ALL_TOOLS, LEVEL_WRITE)]
            assert a.grants(b.id.addr) == []  # undecided: the newcomer may use nothing
            assert await code(b.call(a.id.addr, 64, 1, b"x")) == ERR_FORBIDDEN
            release.set()
            await eventually("on_paired", lambda: paired)
            assert paired[0].allowed() == [Grant("com.acme.x", LEVEL_READ)]
            await eventually("narrowed grants told", lambda: b.granted_by(a.id.addr) == [Grant("com.acme.x", LEVEL_READ)])
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_wants_refused(tmp_path):
    """No wants in the payload (an older device): the application is shown ["*", 2]; it may refuse."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Old")
        try:
            got = []

            def on_wants(p, wants):
                got.append(wants)
                return None, False
            a.on_wants = on_wants
            await join_wants(a, b, None)
            await eventually("asked", lambda: got)
            assert got == [default_grants()]
            await eventually("forgotten", lambda: a.trust.get(b.id.addr) is None)
        finally:
            a.close()
            b.close()
    asyncio.run(run())
