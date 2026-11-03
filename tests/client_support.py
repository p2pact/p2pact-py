"""A fake computer built from the library alone, for the tests of p2pact.client: it serves tools
1, 2 and 4 and a hosted tool, and answers with the messages of the contract fixtures."""
import asyncio
import json
import os

from p2pact.cbor import decode
from p2pact.client import DEFAULT_WANTS, ClientConfig, Computer, P2pactClient, stream_of
from p2pact.client.util import jobj, jstr, normalize, wire
from p2pact.grants import LEVEL_WRITE, Grant, clean_grants
from p2pact.node import ERR_BAD_ARGS, ERR_FORBIDDEN, KIND_COMPUTER, Node, P2PACTError

CONTRACT = os.path.join(os.path.dirname(__file__), "contract", "tools")

CHAT_READ = {"initialize", "session/list", "session/load", "_p2pact/older", "_p2pact/commands", "_p2pact/files",
             "_p2pact/history", "_p2pact/projects", "_p2pact/agents", "_p2pact/image", "_p2pact/diff"}
FLEET_READ = {"fleet/hello", "node/get", "session/list", "session/get", "session/messages", "fleet/watch",
              "fleet/unwatch"}
PLUGINS_READ = {"plugins/list", "plugins/log", "plugins/grants", "plugins/watch", "plugins/unwatch"}


def fixture_exists(dir_: str, name: str) -> bool:
    return os.path.exists(os.path.join(CONTRACT, dir_, name + ".json"))


def fixture(dir_: str, name: str) -> dict:
    """A message of the engine's contract (contract/tools of the engine repository)."""
    with open(os.path.join(CONTRACT, dir_, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def fixture_params(dir_: str, name: str) -> dict:
    return fixture(dir_, name).get("params") or {}


class Seen:
    def __init__(self, tool, method, params, level):
        self.tool, self.method, self.params, self.level = tool, method, params, level


class FakeEngine:
    def __init__(self, dir_: str):
        self.node = Node(dir_, "MacBook Pro")
        self.seen: list[Seen] = []
        self.from_client: asyncio.Queue = asyncio.Queue()  # notifications the client sent (`session/cancel`…)
        self.decide = lambda wants: wants  # what the person grants a newcomer that asked for `wants`
        self.paired: asyncio.Future = asyncio.get_running_loop().create_future()
        self.overrides: dict = {}  # "1:session/list" -> params -> response, in place of the fixture's
        self.watchers: asyncio.Queue = asyncio.Queue()
        self._numbers: dict[int, int] = {}

    @staticmethod
    async def start(dir_: str) -> "FakeEngine":
        e = FakeEngine(dir_)
        n = e.node
        n.kind = KIND_COMPUTER
        await n.listen_udp("127.0.0.1:0")
        n.on_wants = lambda peer, wants: (e.decide(wants), True)
        n.on_paired = lambda p: e.paired.done() or e.paired.set_result(p.addr)
        n.on_event = e._on_event
        n.handle_level(1, 1, lambda peer, level, args: e._rpc(1, level, args, CHAT_READ))
        n.handle_level(2, 1, lambda peer, level, args: e._rpc(2, level, args, FLEET_READ))
        n.handle_level(4, 1, lambda peer, level, args: e._rpc(4, level, args, PLUGINS_READ))
        n.handle_tool("com.example.hello", 1, lambda peer, args: ["hello " + decode(args[0])])
        n.start()
        return e

    def invite(self) -> str:
        return str(self.node.invite(60))

    async def client_addr(self) -> str:
        return await asyncio.wait_for(asyncio.shield(self.paired), 10)

    def close(self):
        self.node.close()

    def _on_event(self, peer, tool, ev, args):
        if tool == 1 and ev == 1:
            msg = normalize(decode(args[0]))
            if isinstance(msg, dict):
                self.from_client.put_nowait(msg)

    def _rpc(self, tool, level, args, reads):
        req = normalize(decode(args[0])) if args else None
        if not isinstance(req, dict):
            raise P2PACTError(ERR_BAD_ARGS, "no request")
        method = req.get("method")
        if not isinstance(method, str):
            raise P2PACTError(ERR_BAD_ARGS, "no method")
        params = jobj(req, "params") or {}
        self.seen.append(Seen(tool, method, params, level))
        # one P2PACT method carries all of the tool: the level is checked on the JSON-RPC method (chat spec §6)
        if method not in reads and level < LEVEL_WRITE:
            raise P2PACTError(ERR_FORBIDDEN, "forbidden")
        ov = self.overrides.get(f"{tool}:{method}")
        resp = ov(params) if ov else {1: self._chat, 2: self._fleet, 4: self._plugins}[tool](method, params)
        return [wire(resp)]

    def _chat(self, method, params):
        if method == "session/load":
            for n in ("session.update.user_message", "session.update.agent_message", "session.update.tool_call"):
                self.notify(1, fixture("p2pact.chat", n + ".notification"))
            return {"jsonrpc": "2.0", "result": {"_meta": {"p2pact": {"older": True}}}}
        stem = method.replace("/", ".")
        if fixture_exists("p2pact.chat", stem + ".response"):
            return fixture("p2pact.chat", stem + ".response")
        return {"jsonrpc": "2.0", "result": {}}

    def _fleet(self, method, params):
        stem = {"fleet/hello": "hello", "session/list": "session-list", "session/get": "session-get",
                "session/messages": "session-messages", "fleet/unwatch": "unwatch", "session/create": "session-create",
                "settings/set": "settings-set"}.get(method)
        if method == "fleet/watch":
            self.watchers.put_nowait(bool(params.get("partial")))
            stem = "watch"
        if method == "session/send":
            stem = "session-send-unknown" if params.get("id") == "нет" else "session-send"
        if method == "node/get":
            return {"jsonrpc": "2.0", "result": fixture("p2pact.fleet", "hello.response")["result"]["node"]}
        return fixture("p2pact.fleet", stem + ".response") if stem else {"jsonrpc": "2.0", "result": {"ok": True}}

    def _plugins(self, method, params):
        stem = method.replace("/", ".")
        if method == "plugins/log" and params.get("name") == "com.example.nope":
            stem = "plugins.log.unknown"
        if fixture_exists("p2pact.plugins", stem + ".response"):
            return fixture("p2pact.plugins", stem + ".response")
        return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "no method " + method}}

    # --- to the client ---

    def notify(self, tool: int, msg: dict):
        """A JSON-RPC notification as the tool's event, on the stream of its session or id."""
        p = jobj(msg, "params") or {}
        stream = stream_of(jstr(p, "sessionId") or jstr(p, "id"))
        n = self._numbers[stream] = self._numbers.get(stream, 0) + 1
        self.node.event_on(self.paired.result(), stream, tool, 1, wire(msg), n)

    async def ask(self, tool: int, msg: dict, session_id: str) -> dict:
        """A request of the client, as the agent device makes it (permissions, questions)."""
        r = await self.node.call_on(self.paired.result(), stream_of(session_id), tool, 1, wire(msg))
        return normalize(decode(r[0]))


def assert_sent(engine: FakeEngine, tool: int, method: str, dir_: str, name: str):
    """What the client sent for `method` equals the fixture's params."""
    s = next((s for s in reversed(engine.seen) if s.tool == tool and s.method == method), None)
    assert s is not None, method + " was not called"
    assert s.params == fixture_params(dir_, name), method


class Rig:
    """A client app paired with a FakeEngine in this process; closes both on exit."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.engine: FakeEngine
        self.client: P2pactClient
        self._n = 0

    def dir(self) -> str:
        self._n += 1
        return str(self.tmp / f"d{self._n}")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        if hasattr(self, "client"):
            self.client.close()
        if hasattr(self, "engine"):
            self.engine.close()

    async def connect(self, wants=None, decide=None) -> Computer:
        """Starts the engine and the client; pairs with `wants` and waits until the computer's
        hello came and the grants it gave (event 0.6) are known."""
        wants = DEFAULT_WANTS if wants is None else wants
        self.engine = await FakeEngine.start(self.dir())
        if decide:
            self.engine.decide = decide
        self.client = await P2pactClient.open(self.dir(), "Test app", ClientConfig(udp="127.0.0.1:0", tcp=None))
        computer = await self.client.pair(self.engine.invite(), wants)
        await computer.when_online(15)
        expected = clean_grants(self.engine.decide(wants))  # the node merges repeats
        await eventually("the grants (event 0.6)", lambda: computer.grants == expected)
        return computer


async def eventually(what, cond, tries=1000):
    for _ in range(tries):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("timeout: " + what)
