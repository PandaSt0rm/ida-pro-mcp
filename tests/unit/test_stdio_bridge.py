import json
import unittest
from unittest import mock

from ida_pro_mcp import stdio_bridge


class FakeResponse:
    def __init__(self, status: int, payload: dict, headers: dict[str, str] | None = None):
        self.status = status
        self._payload = json.dumps(payload).encode("utf-8")
        self._headers = headers or {}

    def getheader(self, name: str, default=None):
        return self._headers.get(name, default)

    def read(self) -> bytes:
        return self._payload


class StdioBridgeTests(unittest.TestCase):
    def test_discovery_is_local_and_excludes_debug_tools(self):
        mcp = stdio_bridge.create_stdio_bridge("http://127.0.0.1:13337")

        with mock.patch.object(stdio_bridge.http.client, "HTTPConnection") as http_connection:
            tools_response = mcp.registry.dispatch(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )
            resources_response = mcp.registry.dispatch(
                {"jsonrpc": "2.0", "id": 2, "method": "resources/list"}
            )
            templates_response = mcp.registry.dispatch(
                {"jsonrpc": "2.0", "id": 3, "method": "resources/templates/list"}
            )

        http_connection.assert_not_called()
        tool_names = {tool["name"] for tool in tools_response["result"]["tools"]}
        self.assertIn("lookup_funcs", tool_names)
        self.assertIn("int_convert", tool_names)
        self.assertNotIn("dbg_start", tool_names)

        resource_uris = {item["uri"] for item in resources_response["result"]["resources"]}
        self.assertIn("ida://idb/metadata", resource_uris)
        self.assertIn("ida://cursor", resource_uris)

        template_uris = {
            item["uriTemplate"]
            for item in templates_response["result"]["resourceTemplates"]
        }
        self.assertIn("ida://struct/{name}", template_uris)

    def test_tool_call_initializes_backend_and_reuses_session(self):
        mcp = stdio_bridge.create_stdio_bridge("http://127.0.0.1:13337")

        init_conn = mock.Mock()
        init_conn.getresponse.return_value = FakeResponse(
            200,
            {
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": stdio_bridge.PROTOCOL_VERSION,
                    "capabilities": {},
                    "serverInfo": {"name": "ida-pro-mcp", "version": "2.0.0"},
                },
                "id": 1,
            },
            headers={"Mcp-Session-Id": "session-1"},
        )
        tool_conn = mock.Mock()
        tool_conn.getresponse.return_value = FakeResponse(
            200,
            {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": '{"ok": true}'}],
                    "structuredContent": {"ok": True},
                    "isError": False,
                },
                "id": 2,
            },
        )

        with mock.patch.object(
            stdio_bridge.http.client,
            "HTTPConnection",
            side_effect=[init_conn, tool_conn],
        ) as http_connection:
            response = mcp.registry.dispatch(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "lookup_funcs",
                        "arguments": {"queries": "main"},
                    },
                }
            )

        self.assertEqual(http_connection.call_count, 2)
        self.assertEqual(response["result"]["structuredContent"], {"ok": True})
        self.assertFalse(response["result"]["isError"])

        init_headers = init_conn.request.call_args.args[3]
        self.assertNotIn("Mcp-Session-Id", init_headers)

        tool_headers = tool_conn.request.call_args.args[3]
        self.assertEqual(tool_headers["Mcp-Session-Id"], "session-1")
        self.assertEqual(tool_headers["Mcp-Protocol-Version"], stdio_bridge.PROTOCOL_VERSION)

    def test_resource_read_proxies_backend_json(self):
        mcp = stdio_bridge.create_stdio_bridge("http://127.0.0.1:13337")

        init_conn = mock.Mock()
        init_conn.getresponse.return_value = FakeResponse(
            200,
            {
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": stdio_bridge.PROTOCOL_VERSION,
                    "capabilities": {},
                    "serverInfo": {"name": "ida-pro-mcp", "version": "2.0.0"},
                },
                "id": 1,
            },
            headers={"Mcp-Session-Id": "session-2"},
        )
        resource_conn = mock.Mock()
        resource_conn.getresponse.return_value = FakeResponse(
            200,
            {
                "jsonrpc": "2.0",
                "result": {
                    "contents": [
                        {
                            "uri": "ida://idb/metadata",
                            "mimeType": "application/json",
                            "text": '{"path": "/tmp/test.i64", "module": "test"}',
                        }
                    ]
                },
                "id": 2,
            },
        )

        with mock.patch.object(
            stdio_bridge.http.client,
            "HTTPConnection",
            side_effect=[init_conn, resource_conn],
        ):
            response = mcp.registry.dispatch(
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "resources/read",
                    "params": {"uri": "ida://idb/metadata"},
                }
            )

        contents = response["result"]["contents"]
        self.assertEqual(len(contents), 1)
        self.assertEqual(contents[0]["uri"], "ida://idb/metadata")
        self.assertIn('"path": "/tmp/test.i64"', contents[0]["text"])

    def test_connection_failures_return_concise_tool_errors(self):
        mcp = stdio_bridge.create_stdio_bridge("http://127.0.0.1:13337")

        conn = mock.Mock()
        conn.request.side_effect = ConnectionRefusedError("boom")

        with mock.patch.object(
            stdio_bridge.http.client,
            "HTTPConnection",
            return_value=conn,
        ):
            response = mcp.registry.dispatch(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {
                        "name": "lookup_funcs",
                        "arguments": {"queries": "main"},
                    },
                }
            )

        self.assertTrue(response["result"]["isError"])
        error_text = response["result"]["content"][0]["text"]
        self.assertIn("Failed to reach IDA backend", error_text)
        self.assertNotIn("Traceback", error_text)


if __name__ == "__main__":
    unittest.main()
