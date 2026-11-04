"""p2pact.client: the chat tool against a fake computer built from the library."""
import asyncio

import pytest

from p2pact.client import (DEFAULT_WANTS, AgentMessage, ChatClient, ConnectionState, ForbiddenError, FailedError,
                           ModeChanged, NoMethodError, NotDeliveredError, NotFoundError, BadArgsError, CallError,
                           OtherUpdate, PermissionOutcome, RpcError, SessionState, ToolCall, UserMessage,
                           QuestionRequest, GrantsChanged, Paired, Online, Forgotten, stream_of)
from p2pact.client.errors import typed
from p2pact.grants import LEVEL_READ, LEVEL_WRITE, Grant
from p2pact.node import KIND_CLIENT, P2PACTError

from p2pact.client import ClientConfig, P2pactClient

from client_support import FakeEngine, Rig, assert_sent, eventually, fixture

CHAT = "p2pact.chat"


async def test_pairing_grants_and_state(tmp_path):
    async with Rig(tmp_path) as rig:
        computer = await rig.connect()
        assert [c.id for c in rig.client.computers()] == [computer.id]
        assert computer.name == "MacBook Pro"
        assert computer.state == ConnectionState.ONLINE
        assert computer.grants == DEFAULT_WANTS  # the wants, as the computer granted them
        assert computer.level(CHAT) == LEVEL_WRITE
        assert computer.level("p2pact.plugins") == LEVEL_READ
        assert not computer.can_write("p2pact.plugins")
        # the engine knows us as a client
        assert rig.engine.node.trust.get(await rig.engine.client_addr()).kind == KIND_CLIENT


async def test_computer_events(tmp_path):
    async with Rig(tmp_path) as rig:
        rig.engine = await FakeEngine.start(rig.dir())
        rig.client = await P2pactClient.open(rig.dir(), "Test app", ClientConfig(udp="127.0.0.1:0", tcp=None))
        events = rig.client.computer_events.stream()
        computer = await rig.client.pair(rig.engine.invite())
        seen = {}
        # the grants are told first as nothing (undecided), then as the person decided
        while not ({Paired, Online} <= set(seen) and seen.get(GrantsChanged) == DEFAULT_WANTS):
            e = await events.next(10)
            seen[type(e)] = getattr(e, "grants", e)
        assert seen[Paired].computer is computer
        rig.client.forget(computer)
        assert isinstance(await events.next(10), Forgotten)
        assert rig.client.computers() == [] and rig.client.computer(computer.id) is None


async def test_initialize_and_list(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        info = await chat.initialize()
        assert_sent(rig.engine, 1, "initialize", "p2pact.chat", "initialize.request")
        assert [a.id for a in info.agents] == ["claude"]
        assert info.agents[0].name == "Claude Code"
        assert info.load_session and info.extensions
        assert info.agent_title == "MacBook Pro"

        lst = await chat.list_sessions()
        assert_sent(rig.engine, 1, "session/list", "p2pact.chat", "session.list.request")
        (s,) = lst.sessions
        assert (s.id, s.cwd, s.agent, s.state) == ("s1", "/w/proj", "claude", SessionState.WORKING)
        assert s.updated_at == "2026-11-03T10:00:00Z"
        assert lst.next_cursor is None
        assert s.raw["sessionId"] == "s1"  # the raw JSON stays reachable
        assert chat.sessions == [s]


async def test_calls_initialize_first_by_themselves(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        await chat.list_all_sessions()
        assert [s.method for s in rig.engine.seen] == ["initialize", "session/list"]


async def test_new_prompt_cancel(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        created = await chat.new_session("/w/app", agent="codex", model="gpt-5", text="собери проект", perms="ask", mid="n1")
        assert created.session_id == "nomad-1"
        assert_sent(rig.engine, 1, "session/new", "p2pact.chat", "session.new.request")

        result = await chat.prompt("s1", "запусти тесты", mid="m1")
        assert result.stop_reason == "end_turn" and not result.duplicate
        assert_sent(rig.engine, 1, "session/prompt", "p2pact.chat", "session.prompt.request")

        chat.cancel("s1")
        n = await asyncio.wait_for(rig.engine.from_client.get(), 10)
        assert n["method"] == "session/cancel" and n["params"]["sessionId"] == "s1"


async def test_load_gives_the_whole_history(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        live = chat.updates.stream()
        loaded = await chat.load_session("s1", "/w/proj")
        assert_sent(rig.engine, 1, "session/load", "p2pact.chat", "session.load.request")
        assert loaded.older
        # all three replayed messages are in the result, in order, though the answer may come first
        user, agent, tool = loaded.updates
        assert isinstance(user, UserMessage) and user.text == "привет" and user.seq == 1
        assert isinstance(agent, AgentMessage) and agent.text == "Привет! Чем помочь?" and agent.seq == 2
        assert agent.time == "2026-11-03T10:00:01Z"
        assert isinstance(tool, ToolCall)
        assert (tool.call.tool_call_id, tool.call.title, tool.call.kind, tool.call.status) == (
            "m3", "Bash: go test", "execute", "completed")
        for _ in range(3):  # and they went to the listeners too
            await live.next(10)


async def test_live_updates_and_changes(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        updates, changes = chat.updates.stream(), chat.session_changes.stream()
        rig.engine.notify(1, fixture("p2pact.chat", "session.update.agent_message.notification"))
        rig.engine.notify(1, fixture("p2pact.chat", "_p2pact.session_changed.notification"))
        u = await updates.next(10)
        assert isinstance(u, AgentMessage) and u.session_id == "s1" and u.text == "Привет! Чем помочь?"
        s = await changes.next(10)
        assert (s.id, s.state, s.agent, s.title) == ("s1", SessionState.IDLE, "claude", "proj")
        assert [x.id for x in chat.sessions] == ["s1"]
        # closing removes it from the known chats
        rig.engine.notify(1, {"jsonrpc": "2.0", "method": "_p2pact/session_changed",
                              "params": {"sessionId": "s1", "_meta": {"p2pact": {"state": "closed"}}}})
        assert (await changes.next(10)).state == SessionState.CLOSED
        assert chat.sessions == []


async def test_unknown_updates_are_kept_raw(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        updates = chat.updates.stream()
        rig.engine.notify(1, {"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": "s1", "update": {"sessionUpdate": "brand_new", "x": 1, "extra": ["y"]}}})
        rig.engine.notify(1, {"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": "s1", "update": {"sessionUpdate": "current_mode_update", "currentModeId": "plan"}}})
        u = await updates.next(10)
        assert isinstance(u, OtherUpdate) and u.type == "brand_new" and u.raw["x"] == 1
        m = await updates.next(10)
        assert isinstance(m, ModeChanged) and m.mode_id == "plan"


async def test_permission_request_answered(tmp_path):
    async with Rig(tmp_path) as rig:
        computer = await rig.connect()
        seen = []

        async def handler(r):  # a handler may be a coroutine function
            seen.append(r)
            await asyncio.sleep(0)
            return r.allow()
        computer.chat.permission_handler = handler
        res = await rig.engine.ask(1, fixture("p2pact.chat", "session.request_permission.request"), "s1")
        assert res == fixture("p2pact.chat", "session.request_permission.response")
        (r,) = seen
        assert r.tool_call.title == "Bash: rm -rf build"
        assert [o.option_id for o in r.options] == ["allow", "always", "deny"]
        assert r.deny().option_id == "deny"
        assert PermissionOutcome.cancelled().is_cancelled


async def test_question_answered(tmp_path):
    async with Rig(tmp_path) as rig:
        computer = await rig.connect()

        def handler(q):  # or a plain function
            assert len(q.questions) == 2 and q.questions[0].header == "База"
            assert [o.label for o in q.questions[0].options] == ["Postgres", "SQLite"]
            assert q.questions[0].options[0].description == "основная"
            assert q.questions[1].multi
            return {"База?": "SQLite", "Что проверить?": QuestionRequest.join(["Тесты"])}
        computer.chat.question_handler = handler
        res = await rig.engine.ask(1, fixture("p2pact.chat", "_p2pact.question.request"), "s1")
        assert res == fixture("p2pact.chat", "_p2pact.question.response")


async def test_request_answered_elsewhere(tmp_path):
    async with Rig(tmp_path) as rig:
        computer = await rig.connect()
        shown = asyncio.Queue()

        async def never(r):  # the person never decides here
            shown.put_nowait(r)
            await asyncio.Event().wait()
        computer.chat.permission_handler = never
        answered = computer.chat.request_answered.stream()
        res = asyncio.ensure_future(rig.engine.ask(1, fixture("p2pact.chat", "session.request_permission.request"), "s1"))
        r = await asyncio.wait_for(shown.get(), 10)
        rig.engine.notify(1, fixture("p2pact.chat", "_p2pact.request_answered.notification"))
        assert (await answered.next(10)).tool_call_id == "w1"
        await asyncio.wait_for(r.answered, 10)
        # the call does not hang: the computer got an error answer
        assert "error" in await asyncio.wait_for(res, 10)


async def test_without_handler_the_computer_hears_no_such_method(tmp_path):
    async with Rig(tmp_path) as rig:
        await rig.connect()
        res = await rig.engine.ask(1, fixture("p2pact.chat", "session.request_permission.request"), "s1")
        assert res["error"]["code"] == -32601
        fs = await rig.engine.ask(1, {"jsonrpc": "2.0", "method": "fs/read_text_file", "params": {"sessionId": "s1"}}, "s1")
        assert fs["error"]["code"] == -32601


@pytest.mark.parametrize("legacy", [False, True], ids=["typed", "legacy"])
async def test_extensions(tmp_path, legacy):
    """Every method against its fixture: as is (typed) and with the typed fields stripped (only `lines`)."""
    async with Rig(tmp_path) as rig:
        computer = await rig.connect(engine_legacy=legacy)
        chat = computer.chat
        assert (await chat.close("s1")).ok
        assert_sent(rig.engine, 1, "initialize", "p2pact.chat", "initialize.request")  # ext 1 and v 2
        assert_sent(rig.engine, 1, "_p2pact/close", "p2pact.chat", "_p2pact.close.request")
        assert (await chat.restart("s1")).ok
        assert_sent(rig.engine, 1, "_p2pact/restart", "p2pact.chat", "_p2pact.restart.request")
        assert (await chat.hide("s1", True)).ok
        assert_sent(rig.engine, 1, "_p2pact/hide", "p2pact.chat", "_p2pact.hide.request")
        assert (await chat.history_open("h1")).ok
        assert_sent(rig.engine, 1, "_p2pact/history_open", "p2pact.chat", "_p2pact.history_open.request")

        page = await chat.older("s1", 3)
        assert_sent(rig.engine, 1, "_p2pact/older", "p2pact.chat", "_p2pact.older.request")
        (m,) = page.messages
        assert (m.seq, m.role, m.text, page.more) == (1, "user", "привет", False)

        (cmd,) = await chat.commands("s1")
        assert_sent(rig.engine, 1, "_p2pact/commands", "p2pact.chat", "_p2pact.commands.request")
        assert (cmd.name, cmd.desc, cmd.hint) == ("review", "Review the changes", "<pr>")
        assert [(a.value, a.desc) for a in cmd.args] == [("main", "base branch")]

        assert await chat.files("s1", "fac") == ["agent/pkg/acpchat/facade.go"]
        assert_sent(rig.engine, 1, "_p2pact/files", "p2pact.chat", "_p2pact.files.request")

        h = await chat.history("", 0)
        assert_sent(rig.engine, 1, "_p2pact/history", "p2pact.chat", "_p2pact.history.request")
        (item,) = h.items
        assert (item.id, item.agent, item.dir, item.title, item.updated, item.count) == (
            "h1", "claude", "/w/proj", "Fix the build", 1793700000000, 12)
        assert (h.query, h.offset, h.total, h.partial) == ("", 0, 2, False)
        assert h.cursor == (None if legacy else 1)  # a legacy line has no cursor

        p = await chat.projects("/w/proj")
        assert_sent(rig.engine, 1, "_p2pact/projects", "p2pact.chat", "_p2pact.projects.request")
        assert p.dirs == ["/w/proj"] and p.project_dirs == {"proj": ["/w/proj", "/w/proj-api"]}
        assert p.dir_repos == {"/w/proj": "git@example.com:team/proj.git"}

        ag = await chat.agents()
        assert_sent(rig.engine, 1, "_p2pact/agents", "p2pact.chat", "_p2pact.agents.request")
        (a,) = ag.agents
        assert (a.id, a.name, a.type, a.enabled, a.models, a.default) == (
            "claude", "Claude Code", "claude", True, ["opus", "sonnet"], "sonnet")
        assert [(x["id"], x["name"]) for x in ag.presets] == [("p1", "Claude Sonnet")]

        diff = await chat.diff("s1")
        assert_sent(rig.engine, 1, "_p2pact/diff", "p2pact.chat", "_p2pact.diff.request")
        assert (diff.files[0].path, diff.files[0].added) == ("a.go", 3)
        assert diff.patch == "diff --git a/a.go b/a.go\n" and not diff.truncated

        image = await chat.image("s1", "/w/proj/shot.png")
        assert_sent(rig.engine, 1, "_p2pact/image", "p2pact.chat", "_p2pact.image.request")
        assert image.error == "not_found" and image.data is None
        assert image.path == "/w/proj/shot.png"
        ok = await chat.image("s1", "/w/proj/ok.png")
        assert ok.error is None and ok.data and ok.data.startswith("iVBOR")
        assert ok.mime == (None if legacy else "image/png")


async def test_initialize_reports_engine_level(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        assert (await chat.initialize()).v == 2


async def test_failed_write_method(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        rig.engine.overrides["1:_p2pact/restart"] = lambda p: {
            "jsonrpc": "2.0", "result": {"ok": False, "error": "not ours", "lines": []}}
        r = await chat.restart("s1")
        assert not r.ok and r.error == "not ours"
        rig.engine.overrides["1:_p2pact/restart"] = lambda p: {
            "jsonrpc": "2.0", "result": {"lines": [{"cmd": "alert", "id": "s1", "text": "boom"}]}}
        r = await chat.restart("s1")
        assert not r.ok and r.error == "boom"


async def test_late_reports(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        reports = chat.reports.stream()
        rig.engine.notify(1, fixture("p2pact.chat", "_p2pact.report.notification"))
        assert (await reports.next(10))["cmd"] == "diff_more"


async def test_listeners_may_be_callbacks(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        got = []
        sub = chat.updates.subscribe(got.append)
        rig.engine.notify(1, fixture("p2pact.chat", "session.update.agent_message.notification"))
        await eventually("callback", lambda: got)
        sub.close()
        rig.engine.notify(1, fixture("p2pact.chat", "session.update.agent_message.notification"))
        await asyncio.sleep(0.2)
        assert len(got) == 1


async def test_read_only_grant_refuses_writes(tmp_path):
    async with Rig(tmp_path) as rig:
        computer = await rig.connect(decide=lambda w: [Grant(CHAT, LEVEL_READ), Grant("p2pact.fleet", LEVEL_READ)])
        assert computer.level(CHAT) == LEVEL_READ and not computer.can_write(CHAT)
        chat = computer.chat
        assert len((await chat.list_sessions()).sessions) == 1  # reading works
        await chat.load_session("s1", "/w/proj")
        # writing is the P2PACT error 4, not a JSON-RPC error
        for write in (lambda: chat.new_session("/w/app"), lambda: chat.prompt("s1", "x"), lambda: chat.close("s1")):
            with pytest.raises(ForbiddenError) as e:
                await write()
            assert e.value.code == 4
            assert isinstance(e.value, P2PACTError)
        # the refused calls did not reach the tool's handler as writes
        assert not [s for s in rig.engine.seen if s.method == "session/prompt" and s.level >= LEVEL_WRITE]


def test_error_codes_are_typed():
    for code, cls in {1: NoMethodError, 2: BadArgsError, 3: NotFoundError, 4: ForbiddenError, 5: FailedError,
                      6: NotDeliveredError}.items():
        t = typed(P2PACTError(code, "x"))
        assert type(t) is cls and t.code == code and str(t) == "x"
    t = typed(P2PACTError(99, "?"))
    assert type(t) is CallError and t.code == 99


async def test_json_rpc_errors_are_rpc_errors(tmp_path):
    async with Rig(tmp_path) as rig:
        chat = (await rig.connect()).chat
        rig.engine.overrides["1:session/list"] = lambda p: {
            "jsonrpc": "2.0", "error": {"code": -32601, "message": "nope", "data": "d"}}
        with pytest.raises(RpcError) as e:
            await chat.list_sessions()
        assert e.value.is_method_not_found and str(e.value) == "nope" and e.value.data == "d"


def test_stream_of():
    assert stream_of(None) == 0 and stream_of("") == 0
    assert stream_of("s1") == stream_of("s1") != stream_of("s2")
    import hashlib
    assert stream_of("s1") == int.from_bytes(hashlib.blake2s(b"s1").digest()[:8], "big")
