"""The local socket road (spec §3) and plugins (spec §2, spec/plugins.md)."""
import asyncio
import contextlib
import os
import shutil
import stat
import sys
import tempfile

import pytest

from p2pact.cbor import decode
from p2pact.grants import LEVEL_WRITE, Grant
from p2pact.node import (ERR_FORBIDDEN, KIND_CLIENT, KIND_COMPUTER, KIND_PLUGIN, KIND_UNKNOWN, P2PACTError)
from p2pact.plugin import ENV_INVITE, ENV_SOCKET, new_plugin
from p2pact.store import Invite

from test_grants import code
from test_kind import eventually
from test_node import echo, make, pair

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the local socket needs Unix sockets")


@pytest.fixture
def sockdir():
    """A directory with a short path: a unix socket path is limited to about 100 bytes."""
    d = tempfile.mkdtemp(prefix="p2p", dir="/tmp")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_local_socket_pairing_and_calls(tmp_path, sockdir):
    async def run():
        sock = os.path.join(sockdir, "node.sock")
        a, b = await make(tmp_path, "Mac", udp=False), await make(tmp_path, "Tool", udp=False)
        try:
            await a.listen_local(sock)
            st = os.stat(sock)
            assert stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
            with pytest.raises(P2PACTError):
                await a.listen_local(sock)  # a second listener on the same node
            b.use_local(sock)
            await pair(a, b)
            await echo(b, a, b"over the socket")
            await echo(a, b, b"local " * 2000)
            assert b.paths(a.id.addr) == ["local"]
            assert b.trust.get(a.id.addr).local  # the dialing side remembers the road
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_local_socket_stale(tmp_path, sockdir):
    """A socket file nobody listens on is replaced; one in use is not; something else is not touched."""
    async def run():
        sock = os.path.join(sockdir, "n.sock")
        a, b = await make(tmp_path, "A", udp=False), await make(tmp_path, "B", udp=False)
        try:
            await a.listen_local(sock)
            with pytest.raises(P2PACTError):
                await b.listen_local(sock)  # a socket in use
            a.close()  # closing the listener removes the file; leave a stale one as a crash would
            assert not os.path.exists(sock)
            import socket
            s = socket.socket(socket.AF_UNIX)
            s.bind(sock)
            s.close()
            assert os.path.exists(sock)
            plain = os.path.join(sockdir, "file")
            open(plain, "w").close()
            with pytest.raises(P2PACTError):
                await b.listen_local(plain)  # a regular file
            assert os.path.exists(plain)
            await b.listen_local(sock)  # the stale one is replaced
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_plugin_pairs_by_env(tmp_path, sockdir, monkeypatch):
    """A plugin: the device starts it with the two variables; it pairs with kind 3, gets the
    install's grants, is reachable over the socket only."""
    async def run():
        sock = os.path.join(sockdir, "host.sock")
        host = await make(tmp_path, "Mac")  # it has UDP: a plugin must still never use it
        plug = None
        try:
            await host.listen_local(sock)
            host.register_tool("com.acme.host")
            host.handle_tool("com.acme.host", 1, lambda peer, args: ["host"])
            grants = [Grant("com.acme.host", LEVEL_WRITE)]
            env = host.plugin_env(3600, grants)
            assert set(env) == {ENV_SOCKET, ENV_INVITE} and env[ENV_SOCKET] == sock
            inv = Invite.parse(env[ENV_INVITE])
            assert inv.hints == {}  # the invite has no hints
            asked = []
            host.on_wants = lambda p, w: asked.append(w) or (None, False)
            for k, v in env.items():
                monkeypatch.setenv(k, v)
            plug, h = await new_plugin(str(tmp_path / "plugin"), "Plugin")
            assert h.addr == host.id.addr and h.kind in (KIND_UNKNOWN, KIND_COMPUTER)
            await eventually("host trusts the plugin", lambda: host.trust.get(plug.id.addr))
            p = host.trust.get(plug.id.addr)
            assert p.kind == KIND_PLUGIN and p.allowed() == grants and p.hints == {}
            assert not asked  # the person was not asked about a plugin
            # the plugin calls the host within its grants, not outside them
            await eventually("hello", lambda: plug.tool_number(host.id.addr, "com.acme.host") is not None)
            res = await asyncio.wait_for(plug.call_tool(host.id.addr, "com.acme.host", 1), 5)
            assert decode(res[0]) == "host"
            assert await code(plug.call(host.id.addr, 64, 1, b"x")) == ERR_FORBIDDEN
            # the host calls the plugin's tool (its grants for the host are the default)
            plug.handle_tool("com.acme.plug", 1, lambda peer, args: ["plugin"])
            await eventually("plugin hello", lambda: host.tool_number(plug.id.addr, "com.acme.plug") is not None)
            res = await asyncio.wait_for(host.call_tool(plug.id.addr, "com.acme.plug", 1), 5)
            assert decode(res[0]) == "plugin"
            assert host.paths(plug.id.addr) == ["local"]
            # single use
            with pytest.raises(P2PACTError):
                await new_plugin(str(tmp_path / "again"), "Again", timeout=2)
            # not a family member
            with pytest.raises(ValueError):
                host.befriend(p)
        finally:
            host.close()
            if plug:
                plug.close()
            await asyncio.sleep(0.05)  # let the closed connections finish before the loop goes
    asyncio.run(run())


def test_plugin_only_over_local(tmp_path, sockdir):
    """A plugin pairing over any other road is refused, and so is a program using a plugin
    invite as something else."""
    async def run():
        sock = os.path.join(sockdir, "host.sock")
        host, other = await make(tmp_path, "Mac"), await make(tmp_path, "Other")
        try:
            await host.listen_local(sock)
            other.kind = KIND_PLUGIN
            with contextlib.suppress(P2PACTError):  # the joiner cannot tell: the host just stays silent
                await other.join(Invite.parse(str(host.invite(60))), 1.5)
            await asyncio.sleep(0.2)
            assert host.trust.get(other.id.addr) is None  # a plugin over UDP is trusted
            other.kind = KIND_CLIENT  # not a plugin: the invite made for programs is not for it
            other.use_local(sock)
            with contextlib.suppress(P2PACTError):
                await other.join(host.plugin_invite(60), 1.5)
            await asyncio.sleep(0.2)
            assert host.trust.get(other.id.addr) is None  # a program invite was used by a client
        finally:
            host.close()
            other.close()
    asyncio.run(run())


def test_plugin_env_needs_socket(tmp_path, monkeypatch):
    async def run():
        n = await make(tmp_path, "Mac", udp=False)
        try:
            with pytest.raises(P2PACTError):
                n.plugin_env(60)  # env without a socket
            monkeypatch.setenv(ENV_SOCKET, "")
            with pytest.raises(P2PACTError):
                await new_plugin(str(tmp_path / "x"), "x")  # a plugin started by nobody
        finally:
            n.close()
    asyncio.run(run())
