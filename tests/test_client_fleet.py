"""p2pact.client: the fleet tool against a fake computer."""
import asyncio

import pytest

from p2pact.client import (ForbiddenError, Notify, OtherEvent, Resync, RpcError, SessionMessages, SessionSpec,
                           SessionsChanged)
from p2pact.grants import LEVEL_READ, Grant

from client_support import Rig, assert_sent, eventually, fixture

ID = "0b7c2e64-1d2a-4f5e-9a10-6c3b8d7e9f01"


async def test_read_methods(tmp_path):
    async with Rig(tmp_path) as rig:
        fleet = (await rig.connect()).fleet
        hello = await fleet.hello()
        assert hello.protocol == "0.2"
        assert (hello.node.name, hello.node.os, hello.node.agents[0].id) == ("MacBook Pro", "darwin", "claude")
        assert hello.node.status["working"] == 1
        assert (await fleet.node()).name == "MacBook Pro"

        (s,) = await fleet.sessions()
        assert (s.id, s.agent, s.dir, s.phase, s.title, s.updated) == (
            ID, "claude", "/Users/me/app", "working", "Починить вход", "2026-10-27T10:00:00Z")
        assert s.raw["status"]["owner"]["node"] == "3f2a9c01d4e5b6a7"
        assert (await fleet.session(ID)).id == ID
        assert_sent(rig.engine, 2, "session/get", "p2pact.fleet", "session-get.request")

        m = await fleet.messages(ID, after=2)
        assert_sent(rig.engine, 2, "session/messages", "p2pact.fleet", "session-messages.request")
        assert m.last == 3 and m.older
        assert (m.messages[0].text, m.messages[0].role) == ("Готово", "assistant")


async def test_watch_delivers_events_in_order(tmp_path):
    async with Rig(tmp_path) as rig:
        fleet = (await rig.connect()).fleet
        events = fleet.events.stream()
        watch = await fleet.watch(False)
        assert_sent(rig.engine, 2, "fleet/watch", "p2pact.fleet", "watch.request")
        assert watch.sessions[0].id == ID

        for n in ("notify-session-changed", "notify-session-messages", "notify-notify"):
            rig.engine.notify(2, fixture("p2pact.fleet", n))
        changed = await events.next(10)
        assert isinstance(changed, SessionsChanged) and changed.sessions[0].phase == "working"
        msgs = await events.next(10)
        assert isinstance(msgs, SessionMessages) and msgs.id == ID
        assert (msgs.messages[0].seq, msgs.messages[0].text) == (4, "Продолжай")
        note = await events.next(10)
        assert isinstance(note, Notify) and note.text == "Агент ждёт ответа"

        rig.engine.notify(2, {"jsonrpc": "2.0", "method": "session/resync", "params": {"id": ID}})
        assert isinstance(r := await events.next(10), Resync) and r.id == ID
        rig.engine.notify(2, {"jsonrpc": "2.0", "method": "something/new", "params": {"k": 1}})
        assert isinstance(o := await events.next(10), OtherEvent) and o.method == "something/new"

        watch.close()
        await eventually("unwatch", lambda: any(s.method == "fleet/unwatch" for s in rig.engine.seen))


async def test_write_methods(tmp_path):
    async with Rig(tmp_path) as rig:
        fleet = (await rig.connect()).fleet
        s = await fleet.create(SessionSpec(agent="claude", dir="/Users/me/app", perms="ask"), "Почини вход")
        assert_sent(rig.engine, 2, "session/create", "p2pact.fleet", "session-create.request")
        assert s.phase == "starting"

        await fleet.send(ID, "Продолжай")
        assert_sent(rig.engine, 2, "session/send", "p2pact.fleet", "session-send.request")

        with pytest.raises(RpcError) as e:
            await fleet.send("нет", "?")
        assert e.value.is_no_such_resource and e.value.code == -32004

        assert await fleet.set_settings({"sleep_after": 15}) == {"sleep_after": 15}
        assert_sent(rig.engine, 2, "settings/set", "p2pact.fleet", "settings-set.request")

        await fleet.answer(ID, wait_id="w1", answers={"Q": "A"})
        assert [s.params for s in rig.engine.seen if s.method == "session/answer"][-1] == {
            "id": ID, "waitId": "w1", "answers": {"Q": "A"}}
        await fleet.interrupt(ID)
        assert (await fleet.close(ID)).warning is None
        await fleet.set_keep(ID, True)
        assert [s.params for s in rig.engine.seen if s.method == "session/setKeep"][-1] == {"id": ID, "on": True}


async def test_read_only_fleet(tmp_path):
    async with Rig(tmp_path) as rig:
        computer = await rig.connect(decide=lambda w: [Grant("p2pact.fleet", LEVEL_READ)])
        fleet = computer.fleet
        assert len(await fleet.sessions()) == 1
        for write in (lambda: fleet.send(ID, "x"), lambda: fleet.create(SessionSpec(agent="claude")),
                      lambda: fleet.interrupt(ID)):
            with pytest.raises(ForbiddenError):
                await write()
        # no grant on the chat at all: even reading is refused
        with pytest.raises(ForbiddenError):
            await computer.chat.list_sessions()
