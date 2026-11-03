# plugin_hello

A minimal P2PACT plugin in Python. It announces the tool `dev.p2pact.example.hello.py`:

- method 1 `hello.greet [name]` returns `"Hello, <name>"` (a read method),
- method 2 `hello.bump` increments a counter (a write method),
- event 1 `tick [counter]` every `HELLO_INTERVAL` seconds (default 5).

The device (for example the Nomad Code engine) hosts the tool for other devices under the same
name and forwards calls and events; read/write is decided by `"read"` in `plugin.json` (methods
not listed need write).

Install into a running engine (Unix only, Python 3.10+; `python3` must be able to `import p2pact`):

```sh
pip install /path/to/p2pact-py
nomad plugin install examples/plugin_hello
nomad plugin log dev.p2pact.example.hello.py
```

The device starts the plugin with `P2PACT_SOCKET` and `P2PACT_INVITE`; it pairs with
`p2pact.plugin.new_plugin`, and its keys live in `P2PACT_PLUGIN_DATA`.
