"""Interop peer for p2pact-tests: a node driven by JSON lines on stdin (see p2pact-go's
cmd/p2pact-interop for the commands). Run: python -m p2pact.interop [data dir] [name]"""
import asyncio
import base64
import json
import sys
import tempfile

from .cbor import decode
from .node import ERR_FAILED, Node, P2PACTError, later
from .store import Invite


async def main():
    dir_ = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="p2pact-interop-")
    node = Node(dir_, sys.argv[2] if len(sys.argv) > 2 else "py")
    # 64.2 echoes too, but answers later: once a 64.1 call has run after it (on its stream, that
    # call is behind it; it passes only if the held call does not hold up the stream)
    held = []

    def echo(peer, args):
        for f in held:
            if not f.done():
                f.set_result(None)
        held.clear()
        return [decode(args[0])]

    def hold(peer, args):
        data = decode(args[0])
        f = asyncio.get_running_loop().create_future()
        held.append(f)

        async def answer():
            try:
                await asyncio.wait_for(f, 30)
            except asyncio.TimeoutError:
                raise P2PACTError(ERR_FAILED, "no call came behind")
            return [data]
        return later(answer())
    node.handle(64, 1, echo)
    node.handle(64, 2, hold)
    node.start()
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=64 << 20)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)

    def say(v):
        sys.stdout.write(json.dumps(v) + "\n")
        sys.stdout.flush()

    while line := await reader.readline():
        try:
            req = json.loads(line)
        except ValueError:
            say({"error": "bad json"})
            continue
        try:
            cmd = req.get("cmd")
            if cmd == "listen":
                if req.get("udp"):
                    await node.listen_udp(req["udp"])
                if "tcp" in req:
                    await node.listen_tcp(req["tcp"])
                say({"addr": node.id.addr, "udp": node.udp.local_addr() if node.udp else "",
                     "tcp": node.tcp.local_addr() if node.tcp else ""})
            elif cmd == "invite":
                say({"invite": str(node.invite(600))})
            elif cmd == "join":
                p = await node.join(Invite.parse(req["invite"]), 15)
                say({"peer": p.addr})
            elif cmd == "known":
                say({"known": node.trust.get(req["peer"]) is not None})
            elif cmd == "call":
                res = await asyncio.wait_for(node.call_on(req["peer"], int(req.get("stream", 0)), 64, 1, base64.b64decode(req["data"])), 60)
                say({"data": base64.b64encode(decode(res[0])).decode()})
            elif cmd == "later":
                stream, data = int(req.get("stream", 0)), base64.b64decode(req["data"])
                first = asyncio.ensure_future(asyncio.wait_for(node.call_on(req["peer"], stream, 64, 2, data), 20))
                await asyncio.sleep(0.1)  # the held call goes first
                try:
                    await asyncio.wait_for(node.call_on(req["peer"], stream, 64, 1, b"behind"), 10)
                except Exception as e:
                    first.cancel()
                    raise RuntimeError(f"the call behind the held one: {e or type(e).__name__}")
                res = await first
                say({"data": base64.b64encode(decode(res[0])).decode()})
            elif cmd == "dict":
                node.add_dict(base64.b64decode(req["raw"]))
                say({"ok": True})
            elif cmd == "dict-state":
                own, using, training = node.dict_state(req["peer"])
                b64 = lambda x: base64.b64encode(x).decode() if x else None
                say({"own": b64(own), "using": b64(using), "training": training})
            elif cmd == "close":
                break
            else:
                say({"error": f"unknown command {cmd}"})
        except Exception as e:
            say({"error": str(e) or type(e).__name__})
    node.close()


if __name__ == "__main__":
    asyncio.run(main())
