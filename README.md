# p2pact-py

Python implementation of **P2PACT — the P2P Agent Chat Transport Protocol**: chat with your AI agents,
and let them chat with each other, across your own devices — no servers, no accounts, over any
connection.

Spec: [p2pact/p2pact](https://github.com/p2pact/p2pact). It interoperates with the
[Go](https://github.com/p2pact/p2pact-go) and [TypeScript](https://github.com/p2pact/p2pact-ts)
implementations — checked by the interop tests in [p2pact-tests](https://github.com/p2pact/p2pact-tests).

Dependencies: `cryptography` (X25519, Ed25519, ChaCha20-Poly1305) and `zstandard`. Noise and
CBOR are implemented here. asyncio, Python 3.10+.

## Use

```python
import asyncio
from p2pact.node import Node
from p2pact.store import Invite

async def main():
    laptop = Node("./laptop-data", "Laptop")        # keys and known devices live here
    await laptop.listen_udp("0.0.0.0:48730")
    await laptop.listen_tcp("0.0.0.0:48730")        # fallback where UDP is blocked
    laptop.handle(1, 2, lambda peer, args: [])        # chat.send: accept a message
    laptop.start()

    invite = str(laptop.invite(600))                 # p2pact1.… — show it as a QR code

    phone = Node("./phone-data", "Phone")
    await phone.listen_udp("0.0.0.0:0")
    phone.start()
    peer = await phone.join(Invite.parse(invite))    # pair once
    await phone.call(peer.addr, 1, 2, 1, "run the tests")

asyncio.run(main())
```

`call_on` / `event_on` send on a stream (one per chat): a loss on one chat does not hold up
the others. A stream's calls and events run one at a time, in the order sent; a handler that
waits long (an agent's turn, a person's answer) returns `later(awaitable)` (from `p2pact.node`):
its stream goes on at once, and the call's result goes when the awaitable is done.

Compression: `node.add_dict(COMMON_DICT)` (from `p2pact.common`) gives the common dictionary
until a device has its own; each device trains one for every device it talks to, on that
conversation only, in the background (`no_learning = True` turns that off).

## Tools, grants, plugins

- Named tools (spec §8): `node.register_tool("com.example.jira")` picks a number from 64 and
  announces it in the hello; `handle_tool(name, method, h)` serves it, `call_tool(peer, name,
  method, ...)` calls a device's tool by name (`tool_number`, `peer_tool_name`, `peer_tools`).
  `handle_tool_all(name, h)` serves every method of a tool with one `h(peer, level, method, args)`
  (a device hosting another program's tool); `unregister_tool(name)` takes it back.
- Grants (spec §8.1): `set_grants(peer, [Grant("com.example.jira", LEVEL_READ)])`, `grant`,
  `revoke_grants`, `mark_read(tool, *methods)`, `handle_level(tool, method, h)`; a call outside the
  grants is error 4. A newcomer may ask with `join(invite, wants=[…])`; the inviting application
  narrows or refuses in `node.on_wants`. `node.kind` (`KIND_COMPUTER`, `KIND_CLIENT`,
  `KIND_PLUGIN`) is told in pairing and the hello.
- Local socket (spec §3, Unix only): `await node.listen_local(path)` on the device,
  `node.plugin_env(ttl, grants)` gives the environment (`P2PACT_SOCKET`, `P2PACT_INVITE`) to start a
  program with; the program calls `node, host = await new_plugin(data_dir, name)` (from
  `p2pact.plugin`). See `examples/plugin_hello`.

## Client SDK (`p2pact.client`)

A typed asyncio client of the public tools (chat, fleet, plugins) for applications that talk to a
computer running the P2PACT engine (the same shape as `p2pact-client` for Kotlin):

```python
from p2pact.client import P2pactClient, AgentMessage

async with await P2pactClient.open("./data", "My app") as client:
    computer = await client.pair("p2pact1.…")      # asks for chat, fleet, plugins:read
    await computer.when_online()
    for s in await computer.chat.list_all_sessions():
        print(s.id, s.state.value, s.title)
    computer.chat.permission_handler = lambda r: r.allow()      # sync or async
    computer.chat.updates.subscribe(lambda u: isinstance(u, AgentMessage) and print(u.text))
    await computer.chat.prompt("s1", "run the tests")           # ends with the agent's turn

    async for e in computer.fleet.events.stream():              # after `await computer.fleet.watch()`
        print(e)
```

Calls are coroutines; they raise `ForbiddenError` (and the other `CallError`s, by P2PACT error code)
or `RpcError` (the tool's own JSON-RPC error). Events are `Events` objects: `subscribe(callback)` or
`stream()` as an async iterator. `computer.grants` / `level()` / `can_write()` tell what the person at
the computer allowed. See `examples/client_cli`.

## Status

Pairing, sessions, UDP and TCP roads, delivery with congestion control, messages,
compression with the common dictionary and per-device dictionaries of its own. Not yet: the relay road, the family tool, Bluetooth.

## Develop

```sh
python -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest
```

`python -m p2pact.interop` is the interop peer used by p2pact-tests.

## License

[Apache License 2.0](LICENSE).
