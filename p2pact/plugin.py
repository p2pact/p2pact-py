"""Plugin helpers (spec §2, local programs): a program a device starts pairs with it over the
local socket. The device side is Node.plugin_env(); this is the plugin side."""
import os

# Environment variables a device gives a program it starts.
ENV_SOCKET = "P2PACT_SOCKET"  # the path of the device's local socket
ENV_INVITE = "P2PACT_INVITE"  # a single-use invite with no hints


async def new_plugin(dir_: str, name: str, timeout: float = 30.0, environ=None):
    """The plugin side: reads P2PACT_SOCKET and P2PACT_INVITE (from environ, os.environ by
    default), dials the socket and pairs with kind KIND_PLUGIN and no wants. dir_ keeps the
    plugin's keys; the node is started. Returns (node, host) — the device the plugin runs on.
    A plugin started again gets a new invite and pairs again."""
    from .node import ERR_FAILED, KIND_PLUGIN, Node, P2PACTError
    from .store import Invite

    env = os.environ if environ is None else environ
    sock, inv = env.get(ENV_SOCKET), env.get(ENV_INVITE)
    if not sock or not inv:
        raise P2PACTError(ERR_FAILED, f"{ENV_SOCKET} and {ENV_INVITE} are not set: not started by a P2PACT device")
    invite = Invite.parse(inv)
    n = Node(dir_, name)
    n.kind = KIND_PLUGIN
    try:
        n.use_local(sock)
        n.start()
        host = await n.join(invite, timeout)
    except BaseException:
        n.close()
        raise
    return n, host
