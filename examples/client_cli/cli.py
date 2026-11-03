"""A small command-line client of the P2PACT engine, built on p2pact.client.

    python cli.py pair <invite>          pair with a computer (invite: p2pact1.… from `nomad invite`)
    python cli.py chats                  list the chats of the paired computers
    python cli.py send <session> <text>  send a message and print the reply
    python cli.py watch                  print the changes of the fleet as they come

State (keys, paired computers) is kept in $P2PACT_CLI_HOME, by default ~/.p2pact-cli.
"""
import asyncio
import os
import sys

from p2pact.client import (AgentMessage, ClientConfig, Computer, ConnectionState, Notify, P2pactClient,
                           SessionMessages, SessionsChanged, Resync)

USAGE = __doc__


async def online(client: P2pactClient) -> list[Computer]:
    """The computers that answer within a few seconds."""
    computers = client.computers()
    if not computers:
        print("no paired computers: run `python cli.py pair <invite>` first", file=sys.stderr)
    out = []
    for c in computers:
        try:
            await c.when_online(15)
        except asyncio.TimeoutError:
            pass
        if c.state == ConnectionState.ONLINE:
            out.append(c)
        else:
            print(f"{c.name}: offline", file=sys.stderr)
    return out


async def pair(client: P2pactClient, invite: str) -> int:
    computer = await client.pair(invite)
    print(f"paired with {computer.name} ({computer.id})")
    # the person at the computer decides what we may use; it tells us right after
    try:
        await computer.when_online(10)
    except asyncio.TimeoutError:
        pass
    await asyncio.sleep(1)
    print("grants: " + ", ".join(f"{g.tool}:{'write' if g.level >= 2 else 'read'}" for g in computer.grants))
    return 0


async def chats(client: P2pactClient) -> int:
    for c in await online(client):
        print(f"# {c.name}")
        for s in await c.chat.list_all_sessions():
            print(f"{s.id}\t{s.state.value}\t{s.agent or '-'}\t{s.title or ''}\t{s.cwd or ''}")
    return 0


async def send(client: P2pactClient, session_id: str, text: str) -> int:
    for c in await online(client):
        chat = c.chat
        if not any(s.id == session_id for s in await chat.list_all_sessions()):
            continue

        async def ask(r):  # the agent may ask: answer on the terminal
            print(f"\n{r.tool_call.title or 'permission'}: allow? [y/N] ", end="", file=sys.stderr, flush=True)
            line = await asyncio.to_thread(sys.stdin.readline)
            return r.allow() if line.strip().lower() == "y" else r.deny()
        chat.permission_handler = ask

        def show(u):
            if u.session_id == session_id and isinstance(u, AgentMessage):
                print(u.text, end="", flush=True)
        chat.updates.subscribe(show)
        result = await chat.prompt(session_id, text)
        print(f"\n[{result.stop_reason}]")
        return 0
    print(f"no such chat: {session_id}", file=sys.stderr)
    return 1


async def watch(client: P2pactClient) -> int:
    computers = await online(client)
    for c in computers:
        def show(e, c=c):
            if isinstance(e, SessionsChanged):
                for s in e.sessions:
                    print(f"{c.name}: {s.id} {s.phase} {s.title or ''}")
            elif isinstance(e, SessionMessages):
                for m in e.messages:
                    print(f"{c.name}: {e.id} [{m.role}] {m.text}")
            elif isinstance(e, Notify):
                print(f"{c.name}: notify: {e.text}")
            elif isinstance(e, Resync):
                print(f"{c.name}: {e.id} resync")
        c.fleet.events.subscribe(show)
        w = await c.fleet.watch()
        print(f"# {c.name}: {len(w.sessions)} sessions, watching")
    if not computers:
        return 1
    await asyncio.Event().wait()  # until Ctrl-C
    return 0


async def main(args: list[str]) -> int:
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 2 if not args else 0
    home = os.environ.get("P2PACT_CLI_HOME") or os.path.expanduser("~/.p2pact-cli")
    client = await P2pactClient.open(home, "p2pact-cli", ClientConfig())
    try:
        cmd = args[0]
        if cmd == "pair" and len(args) > 1:
            return await pair(client, args[1])
        if cmd == "chats":
            return await chats(client)
        if cmd == "send" and len(args) > 2:
            return await send(client, args[1], " ".join(args[2:]))
        if cmd == "watch":
            return await watch(client)
        print(USAGE, file=sys.stderr)
        return 2
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main(sys.argv[1:])))
    except KeyboardInterrupt:
        sys.exit(130)
