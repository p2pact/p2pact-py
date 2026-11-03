"""Grants per trusted device (spec §8.1): which tools a device may use, at which level."""
from dataclasses import dataclass

# Levels of a grant (spec §8.1).
LEVEL_READ = 1  # the methods a tool marks as read, and the tool's events
LEVEL_WRITE = 2  # everything

# The tool name that stands for every tool, present and future.
ALL_TOOLS = "*"


@dataclass(frozen=True)
class Grant:
    """Lets a device use a tool at a level: one element of [[tool name, level]…] (spec §8.1)."""
    tool: str
    level: int


def default_grants() -> list[Grant]:
    """What a person's own device gets: everything, ["*", 2]. A trusted device whose grants were
    never set has it too."""
    return [Grant(ALL_TOOLS, LEVEL_WRITE)]


def grant_level(grants: list[Grant] | None, tool: str) -> int:
    """The level a list of grants gives for a tool name: the highest of the entries that name it
    or "*"; 0 — none. None is the default (everything); an empty list grants nothing."""
    if grants is None:
        return LEVEL_WRITE
    return max((g.level for g in grants if g.tool in (tool, ALL_TOOLS)), default=0)


def is_default_grants(grants: list[Grant] | None) -> bool:
    return grants is None or grants == default_grants()


def grants_wire(grants: list[Grant]) -> list:
    """The grants as they go on the wire: [[tool name, level]…]."""
    return [[g.tool, g.level] for g in grants]


def parse_grants(v) -> list[Grant] | None:
    """Reads [[tool name, level]…]; a malformed entry is skipped. None — not a list."""
    if not isinstance(v, list):
        return None
    out = []
    for e in v:
        if (not isinstance(e, list) or len(e) < 2 or not isinstance(e[0], str) or not isinstance(e[1], int)
                or isinstance(e[1], bool) or e[1] < 1):
            continue
        out.append(Grant(e[0], min(e[1], LEVEL_WRITE)))
    return out


def clean_grants(grants) -> list[Grant]:
    """Drops entries without a tool or a level and merges repeats, keeping the highest."""
    out: list[Grant] = []
    for g in grants:
        if not isinstance(g, Grant):
            g = Grant(*g)
        if not g.tool or g.level < 1:
            continue
        g = Grant(g.tool, min(g.level, LEVEL_WRITE))
        for i, x in enumerate(out):
            if x.tool == g.tool:
                out[i] = Grant(x.tool, max(x.level, g.level))
                break
        else:
            out.append(g)
    return out
