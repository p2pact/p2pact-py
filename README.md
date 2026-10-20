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

## Status

Pairing, sessions, UDP and TCP roads, delivery with congestion control, messages,
compression with dictionaries. Not yet: the relay road, the family tool, Bluetooth.

## Develop

```sh
python -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest
```

`python -m p2pact.interop` is the interop peer used by p2pact-tests.

## License

[Apache License 2.0](LICENSE).
