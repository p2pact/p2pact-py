"""Types of tool 1 `p2pact.chat` (chat spec): ACP with `_meta.p2pact`. Unknown fields are
ignored; every type keeps the JSON it was read from in `raw`."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .util import JsonMap, jbool, jint, jobj, jobjs, jstr, p2pact_meta


@dataclass
class AgentInfo:
    id: str
    name: str
    version: str | None = None
    raw: JsonMap = field(default_factory=dict, repr=False)

    @staticmethod
    def parse(m: JsonMap) -> "AgentInfo":
        return AgentInfo(jstr(m, "id") or "", jstr(m, "name") or jstr(m, "id") or "", jstr(m, "version"), m)


@dataclass
class InitializeResult:
    """The answer to `initialize`: what the computer's chat offers."""
    protocol_version: int
    agent_name: str | None
    agent_title: str | None
    agent_version: str | None
    load_session: bool  # `session/load` works
    agents: list[AgentInfo]  # the agents the computer can start; the first is the default
    extensions: bool  # the computer speaks the `_p2pact/<name>` extensions
    raw: JsonMap = field(default_factory=dict, repr=False)
    v: int = 0  # the extension results level the computer speaks (2: complete typed results)

    @staticmethod
    def parse(m: JsonMap) -> "InitializeResult":
        info = jobj(m, "agentInfo") or {}
        meta = p2pact_meta(m)
        caps = jobj(m, "agentCapabilities") or {}
        return InitializeResult(
            jint(m, "protocolVersion") or 1, jstr(info, "name"), jstr(info, "title"), jstr(info, "version"),
            bool(jbool(caps, "loadSession")), [AgentInfo.parse(a) for a in jobjs(meta, "agents")],
            (jint(meta, "ext") or 0) >= 1, m, jint(meta, "v") or 0)


class SessionState(str, Enum):
    WORKING = "working"
    WAITING = "waiting"  # waits for the person
    IDLE = "idle"
    CLOSED = "closed"
    UNKNOWN = ""

    @staticmethod
    def of(s: str | None) -> "SessionState":
        try:
            return SessionState(s or "")
        except ValueError:
            return SessionState.UNKNOWN


@dataclass
class ChatSession:
    """A chat of a computer: an entry of `session/list` or `_p2pact/session_changed`."""
    id: str
    cwd: str | None
    title: str | None
    agent: str | None
    state: SessionState
    updated_at: str | None  # RFC 3339
    raw: JsonMap = field(default_factory=dict, repr=False, compare=False)

    @staticmethod
    def parse(m: JsonMap) -> "ChatSession":
        meta = p2pact_meta(m)
        return ChatSession(jstr(m, "sessionId") or "", jstr(m, "cwd"), jstr(meta, "title") or jstr(m, "title"),
                           jstr(meta, "agent"), SessionState.of(jstr(meta, "state")),
                           jstr(meta, "updatedAt") or jstr(m, "updatedAt"), m)


@dataclass
class SessionList:
    sessions: list[ChatSession]
    next_cursor: str | None
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class ContentBlock:
    """An ACP content block: text, image, resource_link…"""
    type: str
    text: str | None
    raw: JsonMap = field(default_factory=dict, repr=False)

    @staticmethod
    def parse(m: JsonMap | None) -> "ContentBlock":
        return ContentBlock(jstr(m or {}, "type") or "", jstr(m or {}, "text"), m or {})

    @staticmethod
    def text_block(text: str) -> JsonMap:
        return {"type": "text", "text": text}

    @staticmethod
    def image(mime_type: str, base64_data: str) -> JsonMap:
        return {"type": "image", "mimeType": mime_type, "data": base64_data}


@dataclass
class ToolCallInfo:
    """A tool call of an agent (`tool_call`, `tool_call_update`, the `toolCall` of a permission request)."""
    tool_call_id: str
    title: str | None
    kind: str | None  # ACP's kind: execute, read, edit…
    status: str | None  # pending, in_progress, completed, failed
    raw: JsonMap = field(default_factory=dict, repr=False)

    @staticmethod
    def parse(m: JsonMap) -> "ToolCallInfo":
        return ToolCallInfo(jstr(m, "toolCallId") or "", jstr(m, "title"), jstr(m, "kind"), jstr(m, "status"), m)


@dataclass
class PlanEntry:
    content: str
    priority: str | None
    status: str | None
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class ChatUpdate:
    """A `session/update`: a live message of a chat or a replayed one (`session/load`). `seq`
    numbers the messages of a session; a client that loads a session again skips what it has
    shown (chat spec §8). `raw` is the `update` object. The subclasses are the kinds."""
    session_id: str
    seq: int | None
    time: str | None  # RFC 3339
    raw: JsonMap = field(repr=False)

    @staticmethod
    def parse(session_id: str, u: JsonMap) -> "ChatUpdate":
        meta = p2pact_meta(u)
        seq, time = meta.get("seq"), jstr(meta, "time")
        seq = seq if isinstance(seq, int) and not isinstance(seq, bool) else None
        typ = jstr(u, "sessionUpdate") or ""
        head = (session_id, seq, time, u)
        if typ in _TEXT_KINDS:
            return _TEXT_KINDS[typ](*head, content=ContentBlock.parse(jobj(u, "content")))
        if typ == "tool_call":
            return ToolCall(*head, call=ToolCallInfo.parse(u))
        if typ == "tool_call_update":
            return ToolCallUpdate(*head, call=ToolCallInfo.parse(u))
        if typ == "plan":
            return Plan(*head, entries=[PlanEntry(jstr(e, "content") or "", jstr(e, "priority"), jstr(e, "status"), e)
                                        for e in jobjs(u, "entries")])
        if typ == "current_mode_update":
            return ModeChanged(*head, mode_id=jstr(u, "currentModeId") or "")
        return OtherUpdate(*head, type=typ)


@dataclass
class _Text(ChatUpdate):
    content: ContentBlock = None  # type: ignore[assignment]

    @property
    def text(self) -> str:
        return self.content.text or ""


class UserMessage(_Text):
    pass


class AgentMessage(_Text):
    pass


class AgentThought(_Text):
    pass


_TEXT_KINDS = {"user_message_chunk": UserMessage, "agent_message_chunk": AgentMessage,
               "agent_thought_chunk": AgentThought}


@dataclass
class ToolCall(ChatUpdate):
    call: ToolCallInfo = None  # type: ignore[assignment]


@dataclass
class ToolCallUpdate(ChatUpdate):
    call: ToolCallInfo = None  # type: ignore[assignment]


@dataclass
class Plan(ChatUpdate):
    entries: list[PlanEntry] = field(default_factory=list)


@dataclass
class ModeChanged(ChatUpdate):
    mode_id: str = ""


@dataclass
class OtherUpdate(ChatUpdate):
    """An update this SDK has no type for: read `raw`."""
    type: str = ""


@dataclass
class NewSession:
    session_id: str
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class LoadedSession:
    """What `session/load` gave: the replayed `updates` (all of them have come when it returns)."""
    session_id: str
    updates: list[ChatUpdate]
    older: bool  # there is an earlier part: ChatClient.older()
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class PromptResult:
    stop_reason: str | None
    duplicate: bool  # the `mid` was already executed; nothing was sent again
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class ChatMessage:
    """A message of a conversation, as `_p2pact/older` gives it."""
    seq: int
    role: str
    text: str
    time: str | None
    images: list[str]
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class OlderPage:
    session_id: str
    messages: list[ChatMessage]
    more: bool
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class DiffFile:
    path: str
    added: int
    removed: int
    status: str | None = None


@dataclass
class DiffResult:
    files: list[DiffFile]
    patch: str
    truncated: bool
    error: str | None  # `not_found`, `not_git` or text
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class ImageResult:
    data: str | None  # base64
    error: str | None  # `not_found`, `no_file`, `too_big`, `bad_image`
    raw: JsonMap = field(default_factory=dict, repr=False)
    path: str | None = None
    mime: str | None = None


@dataclass
class CommandArg:
    value: str
    desc: str | None = None


@dataclass
class ChatCommand:
    """A slash command of the chat's agent (`_p2pact/commands`)."""
    name: str
    desc: str | None = None
    hint: str | None = None
    args: list[CommandArg] = field(default_factory=list)


@dataclass
class HistoryItem:
    """A closed conversation of an agent on the device (`_p2pact/history`)."""
    id: str
    agent: str
    dir: str
    title: str
    updated: int  # ms
    project: str | None = None
    count: int | None = None
    open: bool = False  # it is in `session/list` now
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class HistoryPage:
    items: list[HistoryItem]
    query: str
    offset: int  # `from` on the wire
    total: int
    cursor: int | None  # the offset of the next page; None on the last
    partial: bool
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class ProjectsResult:
    dirs: list[str]
    project_dirs: dict[str, list[str]]
    dir_repos: dict[str, str]
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class AgentOption:
    """An agent of `_p2pact/agents` with the models it offers for `new_session()`."""
    id: str
    name: str
    type: str
    enabled: bool
    models: list[str]
    default: str | None = None
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class AgentsResult:
    agents: list[AgentOption]
    presets: list[JsonMap]  # ready-made choices (`id`, `name`, …); the first is the main one
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class OpResult:
    """The answer of a write method (close, restart, hide, history_open)."""
    ok: bool
    error: str | None = None
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class RequestAnswered:
    """`_p2pact/request_answered`: another client answered; stop showing the request."""
    session_id: str
    tool_call_id: str


# --- the computer asks, the application answers ---

@dataclass
class PermissionOption:
    option_id: str
    name: str
    kind: str | None  # allow_once, allow_always, reject_once, reject_always
    description: str | None = None
    raw: JsonMap = field(default_factory=dict, repr=False)


@dataclass
class PermissionOutcome:
    """The outcome of a permission request: Selected(option_id) or Cancelled."""
    option_id: str | None = None  # None — cancelled

    @staticmethod
    def selected(option_id: str) -> "PermissionOutcome":
        return PermissionOutcome(option_id)

    @staticmethod
    def cancelled() -> "PermissionOutcome":
        return PermissionOutcome(None)

    @property
    def is_cancelled(self) -> bool:
        return self.option_id is None


@dataclass
class PermissionRequest:
    """`session/request_permission` (chat spec §6): the agent asks the person to allow
    something. It is also how an agent asks a single question: `tool_call.title` is the
    question and the options are the answers (§9.1). `answered` is done when another client
    answered first (RequestAnswered): stop showing the request."""
    session_id: str
    tool_call: ToolCallInfo
    options: list[PermissionOption]
    raw: JsonMap = field(repr=False)
    answered: "asyncio.Future[None]" = field(repr=False, compare=False, default=None)  # type: ignore[assignment]

    def allow(self) -> PermissionOutcome:
        """The first option that allows, once before always; cancelled if there is none."""
        return self._pick("allow_once", "allow_always")

    def deny(self) -> PermissionOutcome:
        """The first option that rejects."""
        return self._pick("reject_once", "reject_always")

    def select(self, option: PermissionOption) -> PermissionOutcome:
        return PermissionOutcome.selected(option.option_id)

    def _pick(self, *kinds: str) -> PermissionOutcome:
        for k in kinds:
            for o in self.options:
                if o.kind == k:
                    return self.select(o)
        return PermissionOutcome.cancelled()


@dataclass
class QuestionOption:
    label: str
    description: str | None = None


@dataclass
class Question:
    question: str
    header: str | None
    multi: bool  # the answer may take several options
    options: list[QuestionOption]


@dataclass
class QuestionRequest:
    """`_p2pact/question`: several questions, or answers that may take several options (§9.1)."""
    session_id: str
    tool_call_id: str
    questions: list[Question]
    raw: JsonMap = field(repr=False)
    answered: "asyncio.Future[None]" = field(repr=False, compare=False, default=None)  # type: ignore[assignment]

    @staticmethod
    def join(labels: list[str]) -> str:
        """The answer to a `multi` question: the labels joined by ", "."""
        return ", ".join(labels)
