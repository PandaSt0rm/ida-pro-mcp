import ast
import copy
import http.client
import http.server
import json
import os
import sys
import threading
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse, urlunparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcException
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcException
    import zeromcp.jsonrpc as zeromcp_jsonrpc

    sys.path.pop(0)


PROTOCOL_VERSION = "2025-06-18"
DEFAULT_BACKEND_TIMEOUT = 30.0
API_MODULE_FILES = (
    "api_core.py",
    "api_analysis.py",
    "api_memory.py",
    "api_types.py",
    "api_modify.py",
    "api_stack.py",
    "api_python.py",
    "api_resources.py",
)


def _package_version() -> str:
    try:
        return importlib_metadata.version("ida-pro-mcp")
    except importlib_metadata.PackageNotFoundError:
        return "2.0.0"


def _force_mcp_path(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname is None or parsed.port is None:
        raise ValueError(f"Invalid IDA RPC server: {url}")
    return urlunparse(
        (
            parsed.scheme or "http",
            f"{parsed.hostname}:{parsed.port}",
            "/mcp",
            "",
            parsed.query,
            "",
        )
    )


class BackendTransportError(RuntimeError):
    pass


class BackendClient:
    def __init__(self, backend_url: str, timeout: float = DEFAULT_BACKEND_TIMEOUT):
        normalized = urlparse(_force_mcp_path(backend_url))
        self._scheme = normalized.scheme or "http"
        self._host = normalized.hostname or "127.0.0.1"
        self._port = normalized.port or 13337
        self._path = normalized.path or "/mcp"
        if normalized.query:
            self._path = f"{self._path}?{normalized.query}"
        self._timeout = timeout
        self._session_id: str | None = None
        self._initialized = False
        self._initialize_lock = threading.Lock()
        self._request_id = 0

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            self._ensure_initialized()
            response = self._request(
                {
                    "jsonrpc": "2.0",
                    "id": self._next_request_id(),
                    "method": "tools/call",
                    "params": {
                        "name": name,
                        "arguments": arguments or None,
                    },
                }
            )
        except BackendTransportError:
            self._reset_session_state()
            raise
        result = self._extract_result(response)
        if not isinstance(result, dict):
            raise JsonRpcException(-32000, "IDA backend returned an invalid tool response")
        if result.get("isError"):
            raise JsonRpcException(-32000, self._mcp_result_message(result))
        if "structuredContent" in result:
            return result["structuredContent"]
        return self._parse_content_payload(result.get("content"))

    def read_resource(self, uri: str) -> Any:
        try:
            self._ensure_initialized()
            response = self._request(
                {
                    "jsonrpc": "2.0",
                    "id": self._next_request_id(),
                    "method": "resources/read",
                    "params": {"uri": uri},
                }
            )
        except BackendTransportError:
            self._reset_session_state()
            raise
        result = self._extract_result(response)
        if not isinstance(result, dict):
            raise JsonRpcException(
                -32000, "IDA backend returned an invalid resource response"
            )
        if result.get("isError"):
            raise JsonRpcException(-32000, self._mcp_result_message(result))

        contents = result.get("contents")
        if not isinstance(contents, list) or not contents:
            return None

        text = contents[0].get("text")
        if not isinstance(text, str):
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        with self._initialize_lock:
            if self._initialized:
                return
            response = self._request(
                {
                    "jsonrpc": "2.0",
                    "id": self._next_request_id(),
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {
                            "name": "ida-pro-mcp-stdio-bridge",
                            "version": _package_version(),
                        },
                    },
                }
            )
            self._extract_result(response)
            self._initialized = True

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        conn_cls = (
            http.client.HTTPSConnection
            if self._scheme.lower() == "https"
            else http.client.HTTPConnection
        )
        conn = conn_cls(self._host, self._port, timeout=self._timeout)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Mcp-Protocol-Version": PROTOCOL_VERSION,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        try:
            conn.request(
                "POST",
                self._path,
                json.dumps(payload).encode("utf-8"),
                headers,
            )
            response = conn.getresponse()
            session_id = response.getheader("Mcp-Session-Id")
            if session_id:
                self._session_id = session_id
            body = response.read().decode("utf-8", errors="replace")
        except (ConnectionError, OSError, TimeoutError, http.client.HTTPException) as exc:
            raise BackendTransportError(
                f"Failed to reach IDA backend at {self._host}:{self._port}: {exc}"
            ) from exc
        finally:
            conn.close()

        if response.status >= 400:
            detail = body.strip()
            if detail:
                detail = detail.splitlines()[0]
                raise BackendTransportError(
                    f"IDA backend returned HTTP {response.status}: {detail}"
                )
            raise BackendTransportError(f"IDA backend returned HTTP {response.status}")

        if not body.strip():
            raise BackendTransportError("IDA backend returned an empty response")

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise BackendTransportError("IDA backend returned invalid JSON") from exc

        if not isinstance(parsed, dict):
            raise BackendTransportError("IDA backend returned a non-object JSON response")
        return parsed

    def _extract_result(self, response: dict[str, Any]) -> Any:
        if "error" in response:
            error = response.get("error")
            if isinstance(error, dict):
                message = error.get("message") or error.get("data") or str(error)
            else:
                message = str(error)
            raise JsonRpcException(-32000, str(message))
        return response.get("result")

    def _mcp_result_message(self, result: dict[str, Any]) -> str:
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    text = item.get("text")
                    if isinstance(text, str) and text.strip():
                        return text
        return "IDA backend reported an error"

    def _parse_content_payload(self, content: Any) -> Any:
        if not isinstance(content, list):
            return None
        for item in content:
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if not isinstance(text, str):
                continue
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        return None

    def _next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _reset_session_state(self) -> None:
        self._session_id = None
        self._initialized = False


class SourceBridgeBuilder:
    def __init__(self, backend_url: str):
        zeromcp_jsonrpc._LOG_REQUESTS = False
        self.backend = BackendClient(backend_url)
        self.mcp = McpServer("ida-pro-mcp", version=_package_version())
        self._source_dir = Path(__file__).resolve().parent / "ida_mcp"

    def build(self) -> McpServer:
        namespace = self._bootstrap_namespace()
        namespace["_proxy_tool_call"] = self._proxy_tool_call
        namespace["_proxy_resource_read"] = self._proxy_resource_read

        for filename in API_MODULE_FILES:
            self._register_from_file(self._source_dir / filename, namespace)

        return self.mcp

    def _bootstrap_namespace(self) -> dict[str, Any]:
        namespace: dict[str, Any] = {"__builtins__": __builtins__}
        exec("from typing import *", namespace)

        utils_tree = ast.parse((self._source_dir / "utils.py").read_text(encoding="utf-8"))
        defs = []
        for node in utils_tree.body:
            if isinstance(node, ast.ClassDef):
                if any(
                    (isinstance(base, ast.Name) and base.id == "TypedDict")
                    or "TypedDict" in ast.unparse(base)
                    for base in node.bases
                ):
                    defs.append(node)
            elif isinstance(node, ast.Assign):
                if all(isinstance(target, ast.Name) for target in node.targets):
                    defs.append(node)

        self._exec_nodes(defs, namespace, "<bridge_utils_types>")
        return namespace

    def _register_from_file(
        self, path: Path, namespace: dict[str, Any]
    ) -> None:
        tree = ast.parse(path.read_text(encoding="utf-8"))

        defs = []
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.ClassDef)):
                defs.append(node)
        for index, node in enumerate(defs):
            try:
                self._exec_nodes([node], namespace, f"<{path.name}:def:{index}>")
            except Exception:
                continue

        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            resource_uri = self._get_resource_uri(node)
            is_tool = self._has_decorator(node, "tool")
            if not is_tool and resource_uri is None:
                continue
            if self._get_extension(node) == "dbg":
                continue

            proxy_kind = "tool" if is_tool else "resource"
            wrapper = self._compile_proxy_wrapper(
                node=node,
                namespace=namespace,
                filename=path.name,
                proxy_kind=proxy_kind,
                resource_uri=resource_uri,
            )
            if is_tool:
                self.mcp.tool(wrapper)
            else:
                self.mcp.resource(resource_uri)(wrapper)

    def _compile_proxy_wrapper(
        self,
        *,
        node: ast.FunctionDef,
        namespace: dict[str, Any],
        filename: str,
        proxy_kind: str,
        resource_uri: str | None,
    ):
        wrapper_node = copy.deepcopy(node)
        wrapper_node.decorator_list = []

        body: list[ast.stmt] = []
        docstring = ast.get_docstring(node, clean=False)
        if docstring is not None:
            body.append(ast.Expr(value=ast.Constant(value=docstring)))

        proxy_name = "_proxy_tool_call" if proxy_kind == "tool" else "_proxy_resource_read"
        proxy_args = [ast.Call(func=ast.Name(id="locals", ctx=ast.Load()), args=[], keywords=[])]
        if proxy_kind == "tool":
            proxy_args.insert(0, ast.Constant(value=node.name))
        else:
            proxy_args.insert(0, ast.Constant(value=resource_uri))

        body.append(
            ast.Return(
                value=ast.Call(
                    func=ast.Name(id=proxy_name, ctx=ast.Load()),
                    args=proxy_args,
                    keywords=[],
                )
            )
        )
        wrapper_node.body = body

        exec_namespace = dict(namespace)
        self._exec_nodes([wrapper_node], exec_namespace, f"<{filename}:{node.name}>")
        return exec_namespace[node.name]

    def _proxy_tool_call(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            return self.backend.call_tool(name, arguments)
        except BackendTransportError as exc:
            raise JsonRpcException(-32000, str(exc)) from exc

    def _proxy_resource_read(self, uri: str, arguments: dict[str, Any]) -> Any:
        try:
            return self.backend.read_resource(uri.format(**arguments))
        except BackendTransportError as exc:
            raise JsonRpcException(-32000, str(exc)) from exc

    def _exec_nodes(
        self, nodes: list[ast.stmt], namespace: dict[str, Any], filename: str
    ) -> None:
        module = ast.Module(body=nodes, type_ignores=[])
        ast.fix_missing_locations(module)
        exec(compile(module, filename, "exec"), namespace)

    def _has_decorator(self, node: ast.FunctionDef, name: str) -> bool:
        return any(
            isinstance(decorator, ast.Name) and decorator.id == name
            for decorator in node.decorator_list
        )

    def _get_resource_uri(self, node: ast.FunctionDef) -> str | None:
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Name)
                and decorator.func.id == "resource"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                return decorator.args[0].value
        return None

    def _get_extension(self, node: ast.FunctionDef) -> str | None:
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Name)
                and decorator.func.id == "ext"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                return decorator.args[0].value
        return None


def create_stdio_bridge(backend_url: str) -> McpServer:
    return SourceBridgeBuilder(backend_url).build()
