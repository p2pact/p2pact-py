"""Device kind in the pairing payload and the hello (spec §1, §2)."""
import asyncio

from p2pact.cbor import decode, encode
from p2pact.node import KIND_CLIENT, KIND_COMPUTER, KIND_PLUGIN, KIND_UNKNOWN, _pair_kind
from p2pact.store import hints_to_wire

from test_node import echo, make, pair


async def eventually(what, cond, tries=500):
    for _ in range(tries):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("timeout: " + what)


def test_kind_in_pairing_and_hello(tmp_path):
    """The kind goes in the pairing payload and the hello, and is stored in trust on both sides."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Phone")
        try:
            a.kind, b.kind = KIND_COMPUTER, KIND_CLIENT
            await pair(a, b)
            await eventually("kinds in trust", lambda: a.trust.get(b.id.addr) and b.trust.get(a.id.addr)
                             and a.trust.get(b.id.addr).kind == KIND_CLIENT
                             and b.trust.get(a.id.addr).kind == KIND_COMPUTER)
            b.kind = KIND_PLUGIN  # a later change arrives with the next hello
            b._send_info(a.id.addr)
            await eventually("kind from a new hello", lambda: a.trust.get(b.id.addr).kind == KIND_PLUGIN)
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_kind_old_peer(tmp_path):
    """Older devices send a payload and a hello without the kind: they keep working, kind 0."""
    async def run():
        a, b = await make(tmp_path, "Mac"), await make(tmp_path, "Old")
        try:
            assert _pair_kind(decode(encode(["Old", 7, hints_to_wire({}), b"\x01", "linux"]))) == KIND_UNKNOWN
            # a newer payload with fields we do not know yet is read too
            assert _pair_kind(decode(encode(["New", 7, hints_to_wire({}), b"\x01", "linux", KIND_CLIENT,
                                             [["*", 1]], "future"]))) == KIND_CLIENT
            # a device that does not say its kind sends the old payload
            assert len(decode(a._pair_payload())) == 5
            b.kind = KIND_CLIENT
            await pair(a, b)
            await eventually("kind", lambda: a.trust.get(b.id.addr).kind == KIND_CLIENT)
            # an old hello (no kind) changes nothing but the usual
            a._message(b.id.addr, encode([3, 0, 2, "Old", "linux", "old-impl", {}, [], hints_to_wire({})]))
            p = a.trust.get(b.id.addr)
            assert p.name == "Old" and p.kind == KIND_CLIENT
            await echo(a, b, b"still works")
        finally:
            a.close()
            b.close()
    asyncio.run(run())
