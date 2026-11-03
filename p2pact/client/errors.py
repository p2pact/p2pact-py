"""Errors of the client: P2PACT's own (core spec §6) and the tool's JSON-RPC errors."""
from ..node import (ERR_BAD_ARGS, ERR_FAILED, ERR_FORBIDDEN, ERR_NO_METHOD, ERR_NOT_DELIVERED, ERR_NOT_FOUND,
                    P2PACTError)


class CallError(P2PACTError):
    """A P2PACT error: the call never reached the tool. `code` is one of the ERR_* codes; the
    subclasses name the ones an application handles. Also a `p2pact.node.P2PACTError`."""


class NoMethodError(CallError):
    """Error 1: the device has no such tool or method."""


class BadArgsError(CallError):
    """Error 2: the arguments are wrong."""


class NotFoundError(CallError):
    """Error 3: no such thing."""


class ForbiddenError(CallError):
    """Error 4: the grants of the device do not allow the call (spec §8.1)."""


class FailedError(CallError):
    """Error 5: the call failed on the device."""


class NotDeliveredError(CallError):
    """Error 6: not delivered, e.g. a hosted tool whose plugin is gone (spec §8.2)."""


_BY_CODE = {
    ERR_NO_METHOD: NoMethodError, ERR_BAD_ARGS: BadArgsError, ERR_NOT_FOUND: NotFoundError,
    ERR_FORBIDDEN: ForbiddenError, ERR_FAILED: FailedError, ERR_NOT_DELIVERED: NotDeliveredError,
}


def typed(e: Exception) -> Exception:
    """The library's P2PACTError as the exception of its code; anything else stays."""
    if isinstance(e, CallError) or not isinstance(e, P2PACTError):
        return e
    return _BY_CODE.get(e.code, CallError)(e.code, str(e))


class RpcError(Exception):
    """A JSON-RPC error of the tool itself (the call was delivered): `code` is JSON-RPC's
    (-32601 no such method, -32602 params, -32004 no such resource, -32000 failed), `data` the
    optional extra."""
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    NO_SUCH_RESOURCE = -32004
    FAILED = -32000

    def __init__(self, code: int, message: str = "", data=None):
        super().__init__(message)
        self.code, self.data = code, data

    @property
    def is_method_not_found(self) -> bool:
        return self.code == self.METHOD_NOT_FOUND

    @property
    def is_no_such_resource(self) -> bool:
        return self.code == self.NO_SUCH_RESOURCE
