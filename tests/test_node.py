import asyncio
import os

import pytest

from p2pact.cbor import decode, encode
from p2pact.node import ERR_NO_METHOD, Node, P2PACTError
from p2pact.store import Invite


async def make(tmp_path, name, udp=True, tcp=None):
    n = Node(str(tmp_path / name), name)
    if udp:
        await n.listen_udp("127.0.0.1:0")
    if tcp is not None:
        await n.listen_tcp(tcp)
    n.handle(64, 1, lambda peer, args: [decode(args[0])])
    n.start()
    return n


async def pair(a, b):
    p = await b.join(Invite.parse(str(a.invite(60))), 10)
    assert p.addr == a.id.addr
    for _ in range(200):
        if a.trust.get(b.id.addr):
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the owner does not know the joiner")


async def echo(frm, to, data: bytes):
    res = await asyncio.wait_for(frm.call(to.id.addr, 64, 1, data), 30)
    assert decode(res[0]) == data


def test_cbor():
    v = [0, 7, 1, 5, 1, "ок", b"\x01\x02", -5, 2**40, None, True, [1, [2]]]
    assert decode(encode(v)) == v


def test_udp(tmp_path):
    async def run():
        a, b = await make(tmp_path, "laptop"), await make(tmp_path, "phone")
        try:
            await pair(a, b)
            await echo(b, a, b"hello")
            await echo(a, b, "агент закончил задачу ".encode() * 300)
            await echo(a, b, os.urandom(200_000))
            with pytest.raises(P2PACTError) as e:
                await a.call(b.id.addr, 64, 9)
            assert e.value.code == ERR_NO_METHOD
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_tcp_only(tmp_path):
    async def run():
        a = await make(tmp_path, "laptop", udp=False, tcp="127.0.0.1:0")
        b = await make(tmp_path, "phone", udp=False, tcp="")
        try:
            await pair(a, b)
            await echo(b, a, b"over tcp")
            await echo(a, b, b"long " * 2000)
            assert b.paths(a.id.addr) == ["tcp"]
        finally:
            a.close()
            b.close()
    asyncio.run(run())
