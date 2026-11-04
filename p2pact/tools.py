"""Tool names (spec §8): the tools of the spec have the same number on every device; any other
tool has a name (the reverse of a domain) and a number the device picks for itself."""
import re

# Tools given by the spec (§8). Their names are what grants (§8.1) are written in.
FIXED_TOOLS = {
    "p2pact.service": 0,
    "p2pact.chat": 1,
    "p2pact.fleet": 2,
    "p2pact.family": 3,
    "p2pact.plugins": 4,
    "p2pact.term": 5,
}


def fixed_tool(name: str) -> int | None:
    """The number the spec gives a tool name (§8): 0–63, the same on every device. None — the
    name is not one of the spec's."""
    return FIXED_TOOLS.get(name)

# The first number a device may choose for a named tool (spec §8).
FIRST_NAMED_TOOL = 64

_PART = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?\Z")


def valid_tool_name(name: str) -> bool:
    """A tool name of spec §8: lowercase, dot-separated, the reverse of a domain
    ("com.example.jira"). Names under "p2pact." are given by the spec."""
    parts = name.split(".") if isinstance(name, str) else []
    if len(parts) < 2 or parts[0] == "p2pact":
        return False
    return all(_PART.match(p) for p in parts)
