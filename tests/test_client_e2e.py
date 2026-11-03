"""The client SDK against the real Nomad Code engine (Go, `agent/cmd/nomadcode`, TestAppE2E): the
engine runs as a `go test` process on 127.0.0.1 with a random port; nothing of the user's engine
is touched. Only with `P2PACT_ENGINE_E2E=<path to nomad-code/agent>` (Go is needed).

The files in NOMAD_APP_E2E: the engine writes `invite`, `decision` (what it granted), `ready`
(the Stop hook waits), `stop`, `perm` (what the hooks got); the app writes `done`.
NOMAD_APP_E2E_DECIDE is what the person at the engine decides: yes | read | no."""
import asyncio
import os

import pytest

from p2pact.client import ClientConfig, ForbiddenError, P2pactClient, SessionMessages
from p2pact.grants import LEVEL_READ, LEVEL_WRITE, Grant

AGENT = os.environ.get("P2PACT_ENGINE_E2E")
pytestmark = pytest.mark.skipif(not AGENT, reason="P2PACT_ENGINE_E2E is not set")

WANTS = [Grant("p2pact.chat", LEVEL_WRITE), Grant("p2pact.fleet", LEVEL_READ)]


class Engine:
    def __init__(self, agent: str, decide: str, dir_):
        self.agent, self.decide, self.dir = agent, decide, dir_
        self.log = dir_ / "engine.log"
        self.proc = None

    async def start(self):
        env = dict(os.environ, NOMAD_APP_E2E=str(self.dir), NOMAD_APP_E2E_DECIDE=self.decide)
        with open(self.log, "wb") as log:
            self.proc = await asyncio.create_subprocess_exec(
                "go", "test", "-count=1", "-v", "-run", "^TestAppE2E$", "./cmd/nomadcode",
                cwd=self.agent, env=env, stdout=log, stderr=asyncio.subprocess.STDOUT)

    def tail(self, n=3000) -> str:
        return self.log.read_text(errors="replace")[-n:]

    async def wait_file(self, name: str, timeout=120.0) -> str:
        path = self.dir / name
        end = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < end:
            if path.is_file() and path.stat().st_size > 0:
                return path.read_text()
            await asyncio.sleep(0.05)
        raise AssertionError(f"no file {name} from the engine: {self.tail()}")

    async def finish(self):
        (self.dir / "done").write_text("ok")
        try:
            code = await asyncio.wait_for(self.proc.wait(), 60)
        except asyncio.TimeoutError:
            raise AssertionError("the engine did not finish: " + self.tail(2000))
        assert code == 0, self.tail(2000)

    def close(self):
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()


async def eventually(what, cond, timeout=10.0):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("timeout: " + what)


async def test_app_against_engine(tmp_path):
    (tmp_path / "e").mkdir()
    engine = Engine(AGENT, "yes", tmp_path / "e")
    client = None
    try:
        await engine.start()
        client = await P2pactClient.open(str(tmp_path / "data"), "E2E app", ClientConfig(udp="127.0.0.1:0", tcp=None))
        computer = await client.pair(await engine.wait_file("invite"), WANTS, 60)
        await computer.when_online(30)
        assert await engine.wait_file("decision") == "approved"

        chat = computer.chat
        assert (await chat.initialize()).load_session
        (s,) = (await chat.list_sessions()).sessions
        assert s.id == "s1"

        # history
        loaded = await chat.load_session("s1")
        texts = [("u:" if type(u).__name__ == "UserMessage" else "a:") + u.text
                 for u in loaded.updates if type(u).__name__ in ("UserMessage", "AgentMessage")]
        assert "u:привет" in texts and "a:Готово" in texts, texts

        # fleet: read
        fleet = computer.fleet
        assert [x.id for x in await fleet.sessions()] == ["s1"]
        events = fleet.events.stream()
        await fleet.watch()

        # the permission handler answers the engine's question
        asked = asyncio.Queue()

        def on_permission(r):
            asked.put_nowait(r)
            return r.allow()
        chat.permission_handler = on_permission

        # the prompt answers the Stop hook
        await engine.wait_file("ready")
        prompt = asyncio.ensure_future(chat.prompt("s1", "из приложения"))
        assert "из приложения" in await engine.wait_file("stop")
        assert (await asyncio.wait_for(asked.get(), 20)).session_id == "s1"
        assert '"behavior":"allow"' in await engine.wait_file("perm")
        # the turn ends once the permission is answered and the agent is idle again
        assert (await asyncio.wait_for(prompt, 30)).stop_reason == "end_turn"

        # the fleet watch event about the finished turn
        async def reply_event():
            async for e in events:
                if isinstance(e, SessionMessages) and e.id == "s1" and any(m.text == "Сделано" for m in e.messages):
                    return
        await asyncio.wait_for(reply_event(), 20)

        # fleet is read-only for us
        with pytest.raises(ForbiddenError):
            await fleet.send("s1", "нельзя")
        await engine.finish()
    finally:
        if client:
            client.close()
        engine.close()


async def test_read_only_decision_forbids_prompt(tmp_path):
    (tmp_path / "e").mkdir()
    engine = Engine(AGENT, "read", tmp_path / "e")
    client = None
    try:
        await engine.start()
        client = await P2pactClient.open(str(tmp_path / "data"), "E2E app", ClientConfig(udp="127.0.0.1:0", tcp=None))
        computer = await client.pair(await engine.wait_file("invite"), WANTS, 60)
        await computer.when_online(30)
        assert await engine.wait_file("decision") == "read"
        await eventually("read-only level", lambda: computer.level("p2pact.chat") == LEVEL_READ)
        (s,) = (await computer.chat.list_sessions()).sessions
        assert s.id == "s1"
        with pytest.raises(ForbiddenError):
            await asyncio.wait_for(computer.chat.prompt("s1", "нельзя"), 20)
        await engine.finish()
    finally:
        if client:
            client.close()
        engine.close()
