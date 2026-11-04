"""Tool 1 `p2pact.chat`: ACP over P2PACT with the `_p2pact/<name>` extensions (chat spec)."""
from __future__ import annotations

import asyncio
import inspect
import uuid
from typing import TYPE_CHECKING, Awaitable, Callable, Union

from .errors import RpcError
from .models import (AgentInfo, AgentOption, AgentsResult, ChatCommand, CommandArg, HistoryItem, HistoryPage, OpResult,
                     ProjectsResult, ChatMessage, ChatSession, ChatUpdate, ContentBlock, DiffFile, DiffResult, ImageResult,
                     InitializeResult, LoadedSession, NewSession, OlderPage, PermissionOption, PermissionOutcome,
                     PermissionRequest, PromptResult, Question, QuestionOption, QuestionRequest, RequestAnswered,
                     SessionList, SessionState, ToolCallInfo)
from .util import Events, JsonMap, jbool, jint, jobj, jobjs, jstr, jstrs, normalize, p2pact_meta, stream_of, wire

if TYPE_CHECKING:
    from .client import Computer

CHAT_TOOL = 1

PermissionHandler = Callable[[PermissionRequest], Union[PermissionOutcome, Awaitable[PermissionOutcome]]]
QuestionHandler = Callable[[QuestionRequest], Union[dict, Awaitable[dict]]]


def new_mid() -> str:
    """A fresh message id for prompt() and new_session()."""
    return uuid.uuid4().hex[:16]


class ChatClient:
    """Tool 1 `p2pact.chat` of one computer. Methods that read need level 1 on the tool, the
    others level 2; a method the grants refuse fails with ForbiddenError.

    `initialize` goes first by itself (and again after the computer's hello comes anew). All
    calls about one session ride the session's own stream, as the spec says.

    Events: `updates` (live messages and replayed history), `session_changes`,
    `request_answered`, `reports` (late lines of extension commands). Handlers (sync or
    async): `permission_handler(PermissionRequest) -> PermissionOutcome` answers
    `session/request_permission`; `question_handler(QuestionRequest) -> {question: label}`
    answers `_p2pact/question`. Without one the computer gets "no such method" and asks elsewhere.
    """

    def __init__(self, computer: "Computer"):
        self._c = computer
        self.updates: Events[ChatUpdate] = Events()
        self.session_changes: Events[ChatSession] = Events()
        self.request_answered: Events[RequestAnswered] = Events()
        self.reports: Events[JsonMap] = Events()
        self.permission_handler: PermissionHandler | None = None
        self.question_handler: QuestionHandler | None = None
        self._known: dict[str, ChatSession] = {}
        self._collectors: list[tuple[str, list[ChatUpdate]]] = []
        self._pending: dict[str, asyncio.Future] = {}
        self._initialized: asyncio.Future | None = None
        self.info: InitializeResult | None = None  # what `initialize` said, once it has

    @property
    def sessions(self) -> list[ChatSession]:
        """The chats seen so far (from lists and changes), without the closed."""
        return list(self._known.values())

    # --- connection ---

    async def initialize(self) -> InitializeResult:
        """`initialize`: capabilities, the agents the computer offers. It also asks for the
        extension notifications (`_meta.p2pact.ext: 1`). The other calls do it for you."""
        f = self._initialized = asyncio.ensure_future(self._initialize())
        return await asyncio.shield(f)

    async def _initialize(self) -> InitializeResult:
        params = {"protocolVersion": 1, "clientCapabilities": {}, "_meta": {"p2pact": {"ext": 1, "v": 2}}}
        self.info = InitializeResult.parse(await self._c.rpc(CHAT_TOOL, "initialize", params))
        return self.info

    def _reconnected(self):
        self._initialized = None
        self.info = None

    async def _call(self, method: str, params: JsonMap | None, stream: int = 0, timeout: float | None = None) -> JsonMap:
        f = self._initialized
        if f is None or (f.done() and (f.cancelled() or f.exception() is not None)):
            f = self._initialized = asyncio.ensure_future(self._initialize())
        await asyncio.shield(f)
        return await self._c.rpc(CHAT_TOOL, method, params, stream, timeout)

    async def _settled(self, method: str, params: JsonMap | None, stream: int) -> JsonMap:
        """A call, then wait for the events queued on the stream before the result (a result may come ahead of them)."""
        r = await self._call(method, params, stream)
        await self._c.owner.node.after_events(self._c.id, stream)
        return r

    # --- chats ---

    async def list_sessions(self, cwd: str | None = None, cursor: str | None = None) -> SessionList:
        """`session/list`: one page."""
        p = {}
        if cwd is not None:
            p["cwd"] = cwd
        if cursor is not None:
            p["cursor"] = cursor
        r = await self._call("session/list", p)
        sessions = [ChatSession.parse(m) for m in jobjs(r, "sessions")]
        for s in sessions:
            self._remember(s)
        return SessionList(sessions, jstr(r, "nextCursor"), r)

    async def list_all_sessions(self, cwd: str | None = None) -> list[ChatSession]:
        """list_sessions() following the cursor to the end."""
        out: list[ChatSession] = []
        cursor = None
        while True:
            page = await self.list_sessions(cwd, cursor)
            out += page.sessions
            if not page.next_cursor or not page.sessions:
                return out
            cursor = page.next_cursor

    async def new_session(self, cwd: str, agent: str | None = None, model: str | None = None, text: str | None = None,
                          perms: str | None = None, mid: str | None = None) -> NewSession:
        """`session/new`. `agent` is one of InitializeResult.agents (default: the first), `model`
        one of the agent's models, `text` the first task (sent at once), `perms` "skip" or
        "ask". `mid` makes a repeat after a restart harmless."""
        meta: JsonMap = {}
        if agent is not None:
            meta["agent"] = agent
        meta["mid"] = mid or new_mid()
        if model is not None:
            meta["model"] = model
        if text is not None:
            meta["text"] = text
        if perms is not None:
            meta["perms"] = perms
        r = await self._call("session/new", {"cwd": cwd, "mcpServers": [], "_meta": {"p2pact": meta}})
        sid = jstr(r, "sessionId")
        if not sid:
            from .errors import FailedError
            raise FailedError(5, "no sessionId in the answer")
        return NewSession(sid, r)

    async def load_session(self, session_id: str, cwd: str = "") -> LoadedSession:
        """`session/load`: the chat's history comes as updates (also to `updates`) and is in the
        result when it completes. A long chat comes as its tail: `LoadedSession.older`;
        `older()` fetches the earlier part."""
        stream = stream_of(session_id)
        got: list[ChatUpdate] = []
        entry = (session_id, got)
        self._collectors.append(entry)
        try:
            r = await self._settled("session/load", {"sessionId": session_id, "cwd": cwd, "mcpServers": []}, stream)
        finally:
            self._collectors.remove(entry)
        return LoadedSession(session_id, list(got), bool(jbool(p2pact_meta(r), "older")), r)

    async def prompt(self, session_id: str, text: str | list[JsonMap], mid: str | None = None) -> PromptResult:
        """`session/prompt`: it completes when the agent's turn ends (minutes, no timeout); the
        reply comes as `updates` meanwhile. `text` is a string or a list of content blocks.
        `mid` is kept for repeats: send the same one if you do not know whether the first went."""
        blocks = [ContentBlock.text_block(text)] if isinstance(text, str) else text
        params = {"sessionId": session_id, "prompt": blocks, "_meta": {"p2pact": {"mid": mid or new_mid()}}}
        r = await self._call("session/prompt", params, stream_of(session_id), timeout=0)
        return PromptResult(jstr(r, "stopReason"), bool(jbool(r, "duplicate")), r)

    def cancel(self, session_id: str):
        """The notification `session/cancel`: the agent stops the turn."""
        self._c.notify(CHAT_TOOL, "session/cancel", {"sessionId": session_id}, stream_of(session_id))

    async def set_mode(self, session_id: str, mode_id: str) -> JsonMap:
        return await self._call("session/set_mode", {"sessionId": session_id, "modeId": mode_id}, stream_of(session_id))

    async def set_model(self, session_id: str, model_id: str) -> JsonMap:
        return await self._call("session/set_model", {"sessionId": session_id, "modelId": model_id}, stream_of(session_id))

    async def request(self, method: str, params: JsonMap, stream: int | None = None) -> JsonMap:
        """Any ACP or extension method that has no typed call: the `result` object. It rides the
        stream of the params' `sessionId`, or `stream` when given (0: the computer's own stream).
        Like load_session(), it completes after the events the computer sent before the result
        have been handled."""
        return await self._settled(method, params, stream if stream is not None else stream_of(jstr(params, "sessionId")))

    # --- extensions (chat spec §10) ---

    async def command(self, name: str, params: JsonMap | None = None) -> list[JsonMap]:
        """`_p2pact/<name>` and its lines (§9.3): JSON objects with `cmd`. Lines that come later
        arrive in `reports`. A failure the person should see is the line `{"cmd":"alert"}`."""
        params = params or {}
        r = await self._settled("_p2pact/" + name, params, stream_of(jstr(params, "sessionId")))
        return jobjs(r, "lines")

    async def _ext(self, name: str, params: JsonMap) -> tuple[JsonMap, list[JsonMap]]:
        """`_p2pact/<name>`: the typed result and its `lines`. An engine older than `v: 2` may answer before
        late content (commands, agents, history) is ready; that content then comes only as `reports`
        and these methods return it empty (a caller that needs it listens to `reports`)."""
        r = await self._settled("_p2pact/" + name, params, stream_of(jstr(params, "sessionId")))
        return r, jobjs(r, "lines")

    @staticmethod
    def _line(lines: list[JsonMap], cmd: str) -> JsonMap:
        return next((x for x in lines if x.get("cmd") == cmd), {})

    @staticmethod
    def _op(r: JsonMap, lines: list[JsonMap]) -> OpResult:
        if "ok" in r:  # typed; an older engine has only lines: a failure is the `alert` line
            return OpResult(bool(jbool(r, "ok")), jstr(r, "error"), r)
        alert = next((x for x in lines if x.get("cmd") == "alert"), None)
        return OpResult(alert is None, jstr(alert, "text") if alert else None, r)

    async def close(self, session_id: str) -> OpResult:
        """Closes the chat: it leaves the list."""
        return self._op(*await self._ext("close", {"sessionId": session_id}))

    async def restart(self, session_id: str) -> OpResult:
        """Starts the agent of a chat again."""
        return self._op(*await self._ext("restart", {"sessionId": session_id}))

    async def hide(self, session_id: str, on: bool = True) -> OpResult:
        """Hides a chat from the list (on) or shows it again."""
        return self._op(*await self._ext("hide", {"sessionId": session_id, "on": on}))

    async def history_open(self, session_id: str) -> OpResult:
        """`_p2pact/history_open`: brings a closed conversation (the `id` of a HistoryItem) back into the list."""
        return self._op(*await self._ext("history_open", {"sessionId": session_id}))

    async def older(self, session_id: str, before: int) -> OlderPage:
        """`_p2pact/older`: the page of messages just before `before` (the `seq` of the oldest you have)."""
        r, lines = await self._ext("older", {"sessionId": session_id, "before": before})
        src = r if "messages" in r else self._line(lines, "older")
        msgs = [ChatMessage(jint(m, "seq") or 0, jstr(m, "role") or "", jstr(m, "text") or "", jstr(m, "time"),
                            [i for i in (m.get("images") or []) if isinstance(i, str)], m) for m in jobjs(src, "messages")]
        return OlderPage(session_id, msgs, bool(jbool(src, "more")), src)

    async def commands(self, session_id: str) -> list[ChatCommand]:
        """`_p2pact/commands`: the agent's slash commands of the chat (the engine asks the agent: seconds)."""
        r, lines = await self._ext("commands", {"sessionId": session_id})
        items = jobjs(r, "commands") if "commands" in r else jobjs(self._line(lines, "commands"), "list")
        return [ChatCommand(jstr(c, "name") or "", jstr(c, "desc"), jstr(c, "hint"),
                            [CommandArg(jstr(a, "value") or "", jstr(a, "desc")) for a in jobjs(c, "args")]) for c in items]

    async def files(self, session_id: str, query: str) -> list[str]:
        """`_p2pact/files`: files of the chat's folder matching `query` (up to 50), for `@file` completion."""
        r, lines = await self._ext("files", {"sessionId": session_id, "query": query})
        return jstrs(r, "files") if "files" in r else jstrs(self._line(lines, "files"), "list")

    async def history(self, query: str = "", offset: int = 0) -> HistoryPage:
        """`_p2pact/history`: closed conversations of the device's agents, newest first; `HistoryPage.cursor`
        is the `offset` of the next page."""
        r, lines = await self._ext("history", {"query": query, "offset": offset})
        typed = "items" in r
        src = r if typed else self._line(lines, "history")
        items = [HistoryItem(jstr(i, "id") or "", jstr(i, "agent") or "", jstr(i, "dir") or "", jstr(i, "title") or "",
                             jint(i, "updated") or 0, jstr(i, "project"), jint(i, "count"), bool(jbool(i, "open")), i)
                 for i in jobjs(src, "items" if typed else "list")]
        return HistoryPage(items, jstr(src, "query") or "", jint(src, "from") or 0, jint(src, "total") or len(items),
                           jint(src, "cursor"), bool(jbool(src, "partial")), src)

    async def projects(self, cwd: str | None = None) -> ProjectsResult:
        """`_p2pact/projects`: recent folders and folders by project, to start a chat in (`cwd`: one more to describe)."""
        r, lines = await self._ext("projects", {"cwd": cwd} if cwd is not None else {})
        src = r if "dirs" in r else self._line(lines, "projects")
        pd = jobj(src, "project_dirs") or {}
        repos = jobj(src, "dir_repos") or {}
        return ProjectsResult(jstrs(src, "dirs"),
                              {k: [x for x in v if isinstance(x, str)] for k, v in pd.items() if isinstance(v, list)},
                              {k: v for k, v in repos.items() if isinstance(v, str)}, src)

    async def agents(self) -> AgentsResult:
        """`_p2pact/agents`: the agents with the models they offer for `new_session()`, and the presets."""
        r, lines = await self._ext("agents", {})
        if "agents" in r:
            agents, presets = jobjs(r, "agents"), jobjs(r, "presets")
        else:
            agents, presets = jobjs(self._line(lines, "agents"), "list"), jobjs(self._line(lines, "presets"), "list")
        return AgentsResult([AgentOption(jstr(a, "id") or "", jstr(a, "name") or "", jstr(a, "type") or "",
                                         bool(jbool(a, "enabled")), jstrs(a, "models"), jstr(a, "default"), a)
                             for a in agents], presets, r)

    async def diff(self, session_id: str) -> DiffResult:
        """`_p2pact/diff`: the changes in the chat's folder (git)."""
        r, lines = await self._ext("diff", {"sessionId": session_id})
        line = r if ("files" in r or "error" in r) else self._line(lines, "diff")
        files = [DiffFile(jstr(f, "path") or "", jint(f, "added") or 0, jint(f, "removed") or 0, jstr(f, "status"))
                 for f in jobjs(line, "files")]
        return DiffResult(files, jstr(line, "patch") or "", bool(jbool(line, "truncated")), jstr(line, "error"), line)

    async def image(self, session_id: str, path: str) -> ImageResult:
        """`_p2pact/image`: the bytes (base64) of an image a message points to."""
        r, lines = await self._ext("image", {"sessionId": session_id, "path": path})
        line = r if ("data" in r or "error" in r) else self._line(lines, "image")
        return ImageResult(jstr(line, "data"), jstr(line, "error"), line, jstr(line, "path"), jstr(line, "mime"))

    # --- from the computer ---

    def _remember(self, s: ChatSession):
        if not s.id:
            return
        if s.state == SessionState.CLOSED:
            self._known.pop(s.id, None)
        else:
            self._known[s.id] = s

    def _notified(self, args: list):
        """A `notify` event (`session/update`, `_p2pact/…`)."""
        msg = normalize(args[0]) if args else None
        if not isinstance(msg, dict):
            return
        params = jobj(msg, "params") or {}
        method = msg.get("method")
        if method == "session/update":
            sid, upd = jstr(params, "sessionId"), jobj(params, "update")
            if sid is None or upd is None:
                return
            u = ChatUpdate.parse(sid, upd)
            for id_, lst in self._collectors:
                if id_ == sid:
                    lst.append(u)
            self.updates.emit(u)
        elif method == "_p2pact/session_changed":
            s = ChatSession.parse(params)
            self._remember(s)
            self.session_changes.emit(s)
        elif method == "_p2pact/request_answered":
            sid, tc = jstr(params, "sessionId"), jstr(params, "toolCallId")
            if sid is None or tc is None:
                return
            fut = self._pending.pop(f"{sid}/{tc}", None)
            if fut is not None and not fut.done():
                fut.set_result(None)
            self.request_answered.emit(RequestAnswered(sid, tc))
        elif method in ("_p2pact/report", "_nomad/report"):  # _nomad/…: an engine older than the ext flag
            line = jobj(params, "line")
            if line is not None:
                self.reports.emit(line)

    async def _incoming(self, args: list) -> list:
        """A request of the computer (`1.1 rpc`): the answer as a JSON-RPC message."""
        req = normalize(args[0]) if args else None
        if not isinstance(req, dict):
            return _error(RpcError.INVALID_PARAMS, "bad request")
        params = jobj(req, "params") or {}
        method = req.get("method")
        if method == "session/request_permission":
            h = self.permission_handler
            if h is None:
                return _error(RpcError.METHOD_NOT_FOUND, "method not found")
            sid = jstr(params, "sessionId") or ""
            call = ToolCallInfo.parse(jobj(params, "toolCall") or {})
            answered = asyncio.get_running_loop().create_future()
            key = f"{sid}/{call.tool_call_id}"
            self._pending[key] = answered
            request = PermissionRequest(sid, call, [
                PermissionOption(jstr(o, "optionId") or "", jstr(o, "name") or "", jstr(o, "kind"),
                                 jstr(p2pact_meta(o), "description"), o) for o in jobjs(params, "options")], params, answered)

            def reply(o: PermissionOutcome):
                return _result({"outcome": {"outcome": "cancelled"} if o.is_cancelled
                                else {"outcome": "selected", "optionId": o.option_id}})
            return await self._ask(answered, key, lambda: h(request), reply)
        if method in ("_p2pact/question", "_nomad/question"):  # _nomad/…: an engine older than the ext flag
            h = self.question_handler
            if h is None:
                return _error(RpcError.METHOD_NOT_FOUND, "method not found")
            sid, tc = jstr(params, "sessionId") or "", jstr(params, "toolCallId") or ""
            answered = asyncio.get_running_loop().create_future()
            key = f"{sid}/{tc}"
            self._pending[key] = answered
            qs = [Question(jstr(q, "question") or "", jstr(q, "header"), bool(jbool(q, "multi")),
                           [QuestionOption(jstr(o, "label") or "", jstr(o, "description")) for o in jobjs(q, "options")])
                  for q in jobjs(params, "questions")]
            request = QuestionRequest(sid, tc, qs, params, answered)
            return await self._ask(answered, key, lambda: h(request), lambda a: _result({"answers": a}))
        # fs and terminal methods: the agent device does not use our files (chat spec §7)
        return _error(RpcError.METHOD_NOT_FOUND, "method not found")

    async def _ask(self, answered: asyncio.Future, key: str, run, reply) -> list:
        """Runs the application's handler; the request ends when it answers or another client did first."""
        async def go():
            r = run()
            if inspect.isawaitable(r):
                r = await r
            return r
        task = asyncio.ensure_future(go())
        try:
            await asyncio.wait({task, answered}, return_when=asyncio.FIRST_COMPLETED)
            if not task.done():
                # another client answered first: our reply is not needed, but the stream must go on
                task.cancel()
                return _error(RpcError.FAILED, "answered elsewhere")
            try:
                return reply(task.result())
            except asyncio.CancelledError:
                return _error(RpcError.FAILED, "cancelled")
            except Exception as e:
                return _error(RpcError.FAILED, str(e) or "failed")
        finally:
            if self._pending.get(key) is answered:
                del self._pending[key]
            if not task.done():
                task.cancel()


def _result(r) -> list:
    return [wire({"jsonrpc": "2.0", "result": r})]


def _error(code: int, message: str) -> list:
    return [wire({"jsonrpc": "2.0", "error": {"code": code, "message": message}})]
