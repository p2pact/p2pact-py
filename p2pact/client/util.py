"""Helpers of the client: events, reading JSON trees, streams."""
import asyncio
import base64
import inspect
from typing import Any, Callable, Generic, TypeVar

from ..crypto import blake2s

T = TypeVar("T")
JsonMap = dict  # a JSON object as the library reads it: str keys, int/float numbers


class Subscription:
    """Ends a subscription to Events: close() or `with`."""

    def __init__(self, undo: Callable[[], None]):
        self._undo = undo

    def close(self):
        self._undo()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class EventStream(Generic[T]):
    """Events as an async iterator: `async for e in events.stream(): …`. close() ends it."""

    def __init__(self, undo: Callable[[], None]):
        self._q: asyncio.Queue = asyncio.Queue()
        self._undo = undo
        self._closed = False

    def _put(self, v):
        if not self._closed:
            self._q.put_nowait(v)

    def close(self):
        if not self._closed:
            self._closed = True
            self._undo()
            self._q.put_nowait(_END)

    def __aiter__(self):
        return self

    async def __anext__(self) -> T:
        v = await self._q.get()
        if v is _END:
            self._q.put_nowait(_END)
            raise StopAsyncIteration
        return v

    async def next(self, timeout: float | None = None) -> T:
        """The next event, or asyncio.TimeoutError."""
        return await asyncio.wait_for(self.__anext__(), timeout)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


_END = object()


class Events(Generic[T]):
    """A stream of values the application listens to. Listeners run on the event loop, in the
    order the events came; a listener that raises is skipped. A listener may be a coroutine
    function (it is started as a task, so it does not hold up the stream)."""

    def __init__(self):
        self._listeners: list[Callable[[T], Any]] = []
        self._tasks: set[asyncio.Task] = set()

    def subscribe(self, listener: Callable[[T], Any]) -> Subscription:
        self._listeners.append(listener)
        return Subscription(lambda: self._listeners.remove(listener) if listener in self._listeners else None)

    def stream(self) -> EventStream[T]:
        """The events from now on as an async iterator."""
        s: EventStream[T] = EventStream(lambda: None)
        sub = self.subscribe(s._put)
        s._undo = sub.close
        return s

    def emit(self, v: T):
        for listener in list(self._listeners):
            try:
                r = listener(v)
                if inspect.isawaitable(r):
                    t = asyncio.ensure_future(_quiet(r))
                    self._tasks.add(t)
                    t.add_done_callback(self._tasks.discard)
            except Exception:
                pass


async def _quiet(aw):
    try:
        await aw
    except Exception:
        pass


# --- reading JSON trees ---

def jstr(m: dict, k: str) -> str | None:
    v = m.get(k)
    return v if isinstance(v, str) else None


def jint(m: dict, k: str) -> int | None:
    v = m.get(k)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def jbool(m: dict, k: str) -> bool | None:
    v = m.get(k)
    return v if isinstance(v, bool) else None


def jobj(m: dict, k: str) -> dict | None:
    v = m.get(k)
    return v if isinstance(v, dict) else None


def jobjs(m: dict, k: str) -> list[dict]:
    v = m.get(k)
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def jstrs(m: dict, k: str) -> list[str]:
    v = m.get(k)
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def p2pact_meta(m: dict) -> dict:
    """The object at `_meta.p2pact` of an ACP object (chat spec §8)."""
    return jobj(jobj(m, "_meta") or {}, "p2pact") or {}


def normalize(v):
    """A decoded CBOR value as a JSON tree: byte strings become base64 text, keys strings."""
    if isinstance(v, dict):
        return {str(k): normalize(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [normalize(x) for x in v]
    if isinstance(v, (bytes, bytearray)):
        return base64.b64encode(bytes(v)).decode()
    return v


def wire(v):
    """A JSON tree ready for CBOR: whole floats become integers, tuples lists."""
    if isinstance(v, dict):
        return {str(k): wire(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [wire(x) for x in v]
    if isinstance(v, float) and v == v and abs(v) < 1e15 and v == int(v):
        return int(v)
    return v


def stream_of(id_: str | None) -> int:
    """The stream of a session or resource: the first 8 bytes of BLAKE2s(id) as an unsigned
    number, 0 replaced by 1 (chat spec §2); no id — 0."""
    if not id_:
        return 0
    return int.from_bytes(blake2s(id_.encode())[:8], "big") or 1
