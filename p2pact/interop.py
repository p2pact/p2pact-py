"""Interop peer for p2pact-tests: a node driven by JSON lines on stdin (see p2pact-go's
cmd/p2pact-interop for the commands). Run: python -m p2pact.interop [data dir] [name]"""
import asyncio
import base64
import json
import sys
import tempfile

from .cbor import decode
from .node import Node
from .store import Invite


async def main():
    dir_ = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="p2pact-interop-")
    node = Node(dir_, sys.argv[2] if len(sys.argv) > 2 else "py")
    node.handle(64, 1, lambda peer, args: [decode(args[0])])
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
            elif cmd == "dict":
                node.add_dict(base64.b64decode(req["raw"]))
                say({"ok": True})
            elif cmd == "close":
                break
            else:
                say({"error": f"unknown command {cmd}"})
        except Exception as e:
            say({"error": str(e) or type(e).__name__})
    node.close()


if __name__ == "__main__":
    asyncio.run(main())
