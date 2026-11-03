# client_cli

A small command-line client of the P2PACT engine, built on `p2pact.client`.

```sh
pip install -e .                    # from the repository root

# on the computer: create an invite
nomad invite                        # prints p2pact1.…
python examples/client_cli/cli.py pair p2pact1.…     # the person at the computer approves the grants
python examples/client_cli/cli.py chats              # id, state, agent, title, folder of every chat
python examples/client_cli/cli.py send <session> "run the tests"   # streams the reply, asks on permission requests
python examples/client_cli/cli.py watch              # fleet changes, new messages and notifications, until Ctrl-C
```

Keys and paired computers are kept in `$P2PACT_CLI_HOME` (default `~/.p2pact-cli`).
