"""examples/plugin_hello run as a real process against a Python node playing the device that
hosts plugins (the Go engine is not started here)."""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from p2pact.cbor import decode
from test_kind import eventually
from test_node import make

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "plugin_hello")
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the local socket needs Unix sockets")


def test_manifest():
    m = json.load(open(os.path.join(EXAMPLE, "plugin.json")))
    assert m["name"] == "dev.p2pact.example.hello.py" and m["tools"] == [m["name"]]
    assert m["read"] == {m["name"]: [1]} and m["run"][0] == "python3"


def test_plugin_hello_process(tmp_path):
    async def run():
        d = tempfile.mkdtemp(prefix="p2p", dir="/tmp")
        host = await make(tmp_path, "Mac")
        proc = None
        try:
            await host.listen_local(os.path.join(d, "h.sock"))
            ticks = []
            host.on_event = lambda peer, tool, ev, args: ticks.append((host.peer_tool_name(peer, tool), decode(args[0])))
            env = dict(os.environ, **host.plugin_env(60, []), HELLO_INTERVAL="0.2",
                       P2PACT_PLUGIN_DATA=str(tmp_path / "plugin-data"),
                       PYTHONPATH=os.path.join(os.path.dirname(__file__), ".."))
            proc = subprocess.Popen([sys.executable, os.path.join(EXAMPLE, "plugin.py")], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            tool = "dev.p2pact.example.hello.py"
            await eventually("plugin tool", lambda: next(iter(host.trust.list()), None)
                             and host.tool_number(host.trust.list()[0].addr, tool) is not None, 1000)
            plug = host.trust.list()[0].addr
            res = await asyncio.wait_for(host.call_tool(plug, tool, 1, "Ada"), 5)
            assert decode(res[0]) == "Hello, Ada"
            res = await asyncio.wait_for(host.call_tool(plug, tool, 1), 5)
            assert decode(res[0]) == "Hello, world"
            res = await asyncio.wait_for(host.call_tool(plug, tool, 2), 5)
            assert isinstance(decode(res[0]), int)
            await eventually("tick", lambda: any(t[0] == tool for t in ticks), 500)
        finally:
            host.close()
            if proc:
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if proc.returncode not in (0, -15):
                    print(proc.stdout.read().decode())
            shutil.rmtree(d, ignore_errors=True)
    asyncio.run(run())
