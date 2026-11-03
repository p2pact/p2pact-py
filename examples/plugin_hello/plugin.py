"""An example P2PACT plugin in Python: the device starts it, it pairs over the local socket,
announces the tool dev.p2pact.example.hello.py and sends an event every few seconds.

    hello tool (dev.p2pact.example.hello.py)
      method 1  hello.greet [name]  -> "Hello, <name>"   (read: listed in plugin.json "read")
      method 2  hello.bump          -> counter            (write)
      event  1  tick [counter]      every HELLO_INTERVAL seconds (default 5)
"""
import asyncio
import os
import signal
import sys

from p2pact.cbor import decode
from p2pact.plugin import new_plugin

TOOL = "dev.p2pact.example.hello.py"
METHOD_GREET, METHOD_BUMP, EVENT_TICK = 1, 2, 1


async def main() -> int:
    # keys live in the folder the device gives the plugin; the invite and socket come from the
    # environment (P2PACT_INVITE, P2PACT_SOCKET)
    data = os.environ.get("P2PACT_PLUGIN_DATA", "data")
    try:
        node, host = await new_plugin(data, "Hello plugin (Python)")
    except Exception as e:
        print(f"not started by a P2PACT device: {e}", file=sys.stderr)
        return 1
    print(f"paired with {host.name}", flush=True)

    counter = 0

    def greet(peer, args):
        name = decode(args[0]) if args else ""
        return ["Hello, " + (name or "world")]

    def bump(peer, args):
        nonlocal counter
        counter += 1
        return [counter]

    node.handle_tool(TOOL, METHOD_GREET, greet)
    node.handle_tool(TOOL, METHOD_BUMP, bump)
    num = node.register_tool(TOOL, 1)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    try:
        every = float(os.environ.get("HELLO_INTERVAL", "5"))
    except ValueError:
        every = 5.0
    try:
        while True:
            try:
                await asyncio.wait_for(stop.wait(), every if every > 0 else 5.0)
                break
            except asyncio.TimeoutError:
                counter += 1
                try:
                    node.event(host.addr, num, EVENT_TICK, counter)
                except Exception as e:
                    print("tick:", e, file=sys.stderr, flush=True)
    finally:
        node.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
