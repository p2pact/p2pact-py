"""Typed client of P2PACT's public tools (chat, fleet, plugins) for applications: pair with a
computer by its invite, then use `computer.chat`, `computer.fleet`, `computer.plugins`.

    from p2pact.client import P2pactClient

    async with await P2pactClient.open("./data", "My app") as client:
        computer = await client.pair("p2pact1.…")
        chats = await computer.chat.list_sessions()
"""
from .chat import ChatClient, PermissionHandler, QuestionHandler, new_mid
from .client import (CHAT, DEFAULT_WANTS, FLEET, PLUGINS, ClientConfig, Computer, ComputerEvent, ConnectionState,
                     Forgotten, GrantsChanged, Online, P2pactClient, Paired, ToolEvent)
from .errors import (BadArgsError, CallError, FailedError, ForbiddenError, NoMethodError, NotDeliveredError,
                     NotFoundError, RpcError)
from .fleet import (CloseResult, FleetClient, FleetEvent, FleetHello, FleetMessage, FleetMessages, FleetNode,
                    FleetSession, FleetWatch, Notify, OtherEvent, Partial, Resync, SessionMessages, SessionSpec,
                    SessionsChanged)
from .models import (AgentOption, AgentsResult, ChatCommand, CommandArg, HistoryItem, HistoryPage, OpResult,
                     ProjectsResult)
from .models import (AgentInfo, AgentMessage, AgentThought, ChatMessage, ChatSession, ChatUpdate, ContentBlock,
                     DiffFile, DiffResult, ImageResult, InitializeResult, LoadedSession, ModeChanged, NewSession,
                     OlderPage, OtherUpdate, PermissionOption, PermissionOutcome, PermissionRequest, Plan, PlanEntry,
                     PromptResult, Question, QuestionOption, QuestionRequest, RequestAnswered, SessionList,
                     SessionState, ToolCall, ToolCallInfo, ToolCallUpdate, UserMessage)
from .plugins import PluginChanged, PluginGrants, PluginInfo, PluginsClient, PluginStatus
from .util import Events, EventStream, Subscription, stream_of
