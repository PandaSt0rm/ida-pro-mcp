import json
import time
import inspect
import traceback
import logging
from typing import Any, Callable, Literal, get_type_hints, get_origin, get_args, Union, TypedDict, TypeAlias, NotRequired, is_typeddict
from types import UnionType

logger = logging.getLogger("ida_mcp.rpc")

JsonRpcId: TypeAlias = str | int | float | None
JsonRpcParams: TypeAlias = dict[str, Any] | list[Any] | None


def _format_type_name(t: Any) -> str:
    """Format a type for display in error messages"""
    from typing import Annotated
    origin = get_origin(t)
    # Unwrap Annotated types
    if origin is Annotated:
        return _format_type_name(get_args(t)[0])
    if origin is list:
        inner = get_args(t)
        if inner:
            return f"list[{_format_type_name(inner[0])}]"
        return "list"
    if is_typeddict(t):
        # Show TypedDict name and its fields
        hints = {k: v for k, v in getattr(t, '__annotations__', {}).items()}
        fields = ", ".join(f"{k}: {_format_type_name(v)}" for k, v in hints.items())
        return f"{t.__name__}{{{fields}}}"
    if hasattr(t, '__name__'):
        return t.__name__
    return str(t)


class JsonRpcRequest(TypedDict):
    jsonrpc: str
    method: str
    params: NotRequired[JsonRpcParams]
    id: NotRequired[JsonRpcId]

class JsonRpcError(TypedDict):
    code: int
    message: str
    data: NotRequired[Any]

class JsonRpcResponse(TypedDict):
    jsonrpc: str
    result: NotRequired[Any]
    error: NotRequired[JsonRpcError]
    id: JsonRpcId

class JsonRpcException(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data


def _summarize_params(params: JsonRpcParams, max_len: int = 100) -> str:
    """Create a brief summary of params for logging."""
    if params is None:
        return ""
    try:
        s = json.dumps(params, default=str)
        if len(s) > max_len:
            return s[:max_len] + "..."
        return s
    except Exception:
        return "<unprintable>"


class JsonRpcRegistry:
    def __init__(self):
        self.methods: dict[str, Callable] = {}
        self._cache: dict[Callable, tuple[inspect.Signature, dict, list[str]]] = {}
        self.redact_exceptions = False

    def method(self, func: Callable, name: str | None = None) -> Callable:
        self.methods[name or func.__name__] = func # type: ignore
        return func

    def dispatch(self, request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        try:
            if not isinstance(request, dict):
                request = json.loads(request)
            if not isinstance(request, dict):
                return self._error(None, -32600, "Invalid request: must be a JSON object")
        except Exception as e:
            logger.error(f"JSON parse error: {e}")
            return self._error(None, -32700, "JSON parse error", str(e))

        if request.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "Invalid request: 'jsonrpc' must be '2.0'")

        method = request.get("method")
        if method is None:
            return self._error(None, -32600, "Invalid request: 'method' is required")
        if not isinstance(method, str):
            return self._error(None, -32600, "Invalid request: 'method' must be a string")

        request_id: JsonRpcId = request.get("id")
        is_notification = "id" not in request
        params: JsonRpcParams = request.get("params")

        # Log the request
        params_summary = _summarize_params(params)
        logger.info(f">>> {method}({params_summary}) [id={request_id}]")
        start_time = time.time()

        try:
            result = self._call(method, params)
            elapsed = time.time() - start_time
            logger.info(f"<<< {method} completed in {elapsed:.3f}s [id={request_id}]")
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id,
            }
        except JsonRpcException as e:
            elapsed = time.time() - start_time
            logger.warning(f"<<< {method} failed ({elapsed:.3f}s): [{e.code}] {e.message} [id={request_id}]")
            if is_notification:
                return None
            return self._error(request_id, e.code, e.message, e.data)
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"<<< {method} exception ({elapsed:.3f}s): {type(e).__name__}: {e} [id={request_id}]")
            logger.debug(f"Traceback:\n{traceback.format_exc()}")
            if is_notification:
                return None
            error = self.map_exception(e)
            return self._error(request_id, error["code"], error["message"], error.get("data"))

    def map_exception(self, e: Exception) -> JsonRpcError:
        if self.redact_exceptions:
            return {
                "code": -32603,
                "message": f"Internal Error: {str(e)}",
            }
        return {
            "code": -32603,
            "message": "\n".join(traceback.format_exception(e)).strip() + "\n\nPlease report a bug!",
        }

    def _call(self, method: str, params: Any) -> Any:
        if method not in self.methods:
            raise JsonRpcException(-32601, f"Method '{method}' not found")

        func = self.methods[method]

        # Check for cached reflection data
        if func not in self._cache:
            sig = inspect.signature(func)
            hints = get_type_hints(func)
            hints.pop("return", None)

            # Determine required vs optional parameters
            required_params = []
            for param_name, param in sig.parameters.items():
                if param.default is inspect.Parameter.empty:
                    required_params.append(param_name)

            self._cache[func] = (sig, hints, required_params)

        sig, hints, required_params = self._cache[func]

        # Handle None params
        if params is None:
            if len(required_params) == 0:
                return func()
            else:
                raise JsonRpcException(-32602, "Missing required params")

        # Convert list params to dict by parameter names
        if isinstance(params, list):
            if len(params) < len(required_params):
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: expected at least {len(required_params)} arguments, got {len(params)}"
                )
            if len(params) > len(sig.parameters):
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: expected at most {len(sig.parameters)} arguments, got {len(params)}"
                )
            params = dict(zip(sig.parameters.keys(), params))

        # Validate dict params
        if isinstance(params, dict):
            # Check all required params are present
            missing = set(required_params) - set(params.keys())
            if missing:
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: missing required parameters: {list(missing)}"
                )

            # Check no extra params
            extra = set(params.keys()) - set(sig.parameters.keys())
            if extra:
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: unexpected parameters: {list(extra)}"
                )

            validated_params = {}
            for param_name, value in params.items():
                # If no type hint, pass through without validation
                if param_name not in hints:
                    validated_params[param_name] = value
                    continue

                # Has type hint, validate
                expected_type = hints[param_name]

                # Inline type validation
                origin = get_origin(expected_type)
                args = get_args(expected_type)

                # Handle None/null
                if value is None:
                    if expected_type is not type(None):
                        # Check if None is allowed in a Union
                        if not (origin in (Union, UnionType) and type(None) in args):
                            raise JsonRpcException(-32602, f"Invalid params: {param_name} cannot be null")
                    validated_params[param_name] = None
                    continue

                # Handle Union types (int | str, Optional[int], etc.)
                if origin in (Union, UnionType):
                    type_matched = False
                    for arg_type in args:
                        if arg_type is type(None):
                            continue

                        arg_origin = get_origin(arg_type)
                        check_type = arg_origin if arg_origin is not None else arg_type

                        # TypedDict: check it's a dict AND has required fields
                        if is_typeddict(arg_type):
                            if isinstance(value, dict):
                                required_keys = getattr(arg_type, '__required_keys__', set())
                                if required_keys <= set(value.keys()):
                                    type_matched = True
                                    break
                            continue

                        if isinstance(value, check_type):
                            type_matched = True
                            break

                    if not type_matched:
                        expected_types = [_format_type_name(t) for t in args if t is not type(None)]
                        hint = ""
                        # Detect likely double-encoded JSON
                        if isinstance(value, str) and value.strip().startswith(('[', '{')):
                            hint = " (value looks like JSON string - don't stringify objects, pass them directly)"
                        raise JsonRpcException(-32602, f"Invalid params: {param_name} expected {' | '.join(expected_types)}, got {type(value).__name__}{hint}")
                    validated_params[param_name] = value
                    continue

                # Handle Literal types
                if origin is Literal:
                    allowed_values = args
                    if value not in allowed_values:
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} must be one of {', '.join(repr(v) for v in allowed_values)}, got {value!r}"
                        )
                    validated_params[param_name] = value
                    continue

                # Handle generic types (list[X], dict[K,V])
                if origin is not None:
                    if not isinstance(value, origin):
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} expected {origin.__name__}, got {type(value).__name__}"
                        )
                    validated_params[param_name] = value
                    continue

                # Handle TypedDict (must check before basic types)
                if is_typeddict(expected_type):
                    if not isinstance(value, dict):
                        hint = ""
                        if isinstance(value, str) and value.strip().startswith(('[', '{')):
                            hint = " (value looks like JSON string - don't stringify objects, pass them directly)"
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} expected {_format_type_name(expected_type)}, got {type(value).__name__}{hint}"
                        )
                    # Check required fields
                    required_keys = getattr(expected_type, '__required_keys__', set())
                    missing = required_keys - set(value.keys())
                    if missing:
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} missing required fields: {', '.join(sorted(missing))}. Expected {_format_type_name(expected_type)}"
                        )
                    validated_params[param_name] = value
                    continue

                # Handle Any
                if expected_type is Any:
                    validated_params[param_name] = value
                    continue

                # Handle basic types
                if isinstance(expected_type, type):
                    # Allow int -> float conversion
                    if expected_type is float and isinstance(value, int):
                        validated_params[param_name] = float(value)
                        continue
                    if not isinstance(value, expected_type):
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} expected {expected_type.__name__}, got {type(value).__name__}"
                        )
                    validated_params[param_name] = value
                    continue

            return func(**validated_params)

        else:
            raise JsonRpcException(-32602, "Invalid params: must be array or object")

    def _error(self, request_id: JsonRpcId, code: int, message: str, data: Any = None) -> JsonRpcResponse | None:
        error: JsonRpcError = {
            "code": code,
            "message": message,
        }
        if data is not None:
            error["data"] = data
        return {
            "jsonrpc": "2.0",
            "error": error,
            "id": request_id,
        }
