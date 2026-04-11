import json
import os
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from ida_pro_mcp import server


class GenerateMcpConfigTests(unittest.TestCase):
    def test_generate_mcp_config_stdio_for_generic_clients_uses_command_and_args(self):
        command = ["/usr/bin/python3", "/repo/server.py", "--ida-rpc", "http://x"]
        env = {"PYTHONPATH": "/repo/src"}
        with mock.patch.object(
            server, "_build_stdio_command", return_value=(command, env)
        ):
            config = server.generate_mcp_config(
                client_name="Generic",
                transport="stdio",
            )

        self.assertEqual(
            config,
            {
                "command": "/usr/bin/python3",
                "args": ["/repo/server.py", "--ida-rpc", "http://x"],
                "env": {"PYTHONPATH": "/repo/src"},
            },
        )

    def test_generate_mcp_config_stdio_for_opencode_uses_local_shape(self):
        command = ["/usr/bin/python3", "/repo/server.py", "--ida-rpc", "http://x"]
        env = {"PYTHONPATH": "/repo/src"}
        with mock.patch.object(
            server, "_build_stdio_command", return_value=(command, env)
        ):
            config = server.generate_mcp_config(
                client_name="Opencode",
                transport="stdio",
            )

        self.assertEqual(
            config,
            {
                "type": "local",
                "command": command,
                "enabled": True,
                "environment": env,
            },
        )

    def test_generate_mcp_config_for_opencode_http_uses_remote_shape(self):
        config = server.generate_mcp_config(
            client_name="Opencode",
            transport="streamable-http",
        )

        self.assertEqual(
            config,
            {
                "type": "remote",
                "url": "http://127.0.0.1:13337/mcp",
                "enabled": True,
            },
        )

    def test_generate_mcp_config_rejects_sse_for_opencode(self):
        with self.assertRaisesRegex(
            ValueError,
            "OpenCode MCP config does not support SSE",
        ):
            server.generate_mcp_config(client_name="Opencode", transport="sse")

    def test_transport_helpers_normalize_paths_and_detect_transport_type(self):
        self.assertEqual(
            server.normalize_transport_url("http://127.0.0.1:7331"),
            "http://127.0.0.1:7331/mcp",
        )
        self.assertEqual(
            server.normalize_transport_url("http://127.0.0.1:7331/sse"),
            "http://127.0.0.1:7331/sse",
        )
        self.assertEqual(
            server.force_mcp_path("http://127.0.0.1:7331/sse"),
            "http://127.0.0.1:7331/mcp",
        )
        self.assertEqual(
            server.infer_http_transport_type("http://127.0.0.1:7331/sse"),
            "sse",
        )
        self.assertEqual(
            server.infer_http_transport_type("http://127.0.0.1:7331/mcp"),
            "http",
        )


class ClientConfigPathTests(unittest.TestCase):
    def test_get_project_configs_includes_root_level_opencode_json(self):
        configs = server.get_project_configs("/tmp/project")
        self.assertEqual(configs["Opencode"], ("/tmp/project", "opencode.json"))

    def test_get_global_configs_uses_documented_opencode_location(self):
        configs = server.get_global_configs()
        config_dir, config_file = configs["Opencode"]

        self.assertEqual(config_file, "opencode.json")
        self.assertTrue(
            config_dir.endswith(os.path.join(".config", "opencode")),
            config_dir,
        )


class DispatchProxyTests(unittest.TestCase):
    def test_dispatch_proxy_keeps_initialize_local(self):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        }
        expected = {"jsonrpc": "2.0", "result": {"ok": True}, "id": 1}

        with (
            mock.patch.object(server, "dispatch_original", return_value=expected) as original,
            mock.patch.object(server.http.client, "HTTPConnection") as http_connection,
        ):
            response = server.dispatch_proxy(request)

        self.assertEqual(response, expected)
        original.assert_called_once_with(request)
        http_connection.assert_not_called()

    def test_dispatch_proxy_keeps_notifications_local(self):
        request = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }

        with (
            mock.patch.object(server, "dispatch_original", return_value=None) as original,
            mock.patch.object(server.http.client, "HTTPConnection") as http_connection,
        ):
            response = server.dispatch_proxy(request)

        self.assertIsNone(response)
        original.assert_called_once_with(request)
        http_connection.assert_not_called()

    def test_dispatch_proxy_proxies_non_local_requests_over_http(self):
        request = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/list",
        }
        conn = mock.Mock()
        conn.getresponse.return_value.read.return_value = (
            b'{"jsonrpc":"2.0","result":{"tools":[]},"id":7}'
        )

        with mock.patch.object(
            server.http.client,
            "HTTPConnection",
            return_value=conn,
        ) as http_connection:
            response = server.dispatch_proxy(request)

        self.assertEqual(response["result"], {"tools": []})
        http_connection.assert_called_once_with("127.0.0.1", 13337, timeout=30)
        conn.request.assert_called_once()
        method, path, body, headers = conn.request.call_args.args
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/mcp")
        self.assertEqual(json.loads(body), request)
        self.assertEqual(headers, {"Content-Type": "application/json"})
        conn.close.assert_called_once()

    def test_dispatch_proxy_returns_connection_error_payload(self):
        request = {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/list",
        }
        conn = mock.Mock()
        conn.request.side_effect = ConnectionRefusedError("boom")

        with mock.patch.object(
            server.http.client,
            "HTTPConnection",
            return_value=conn,
        ):
            response = server.dispatch_proxy(request)

        self.assertEqual(response["error"]["code"], -32000)
        self.assertEqual(response["id"], 9)
        self.assertEqual(response["error"]["data"], "boom")
        self.assertIn("Failed to connect to IDA Pro!", response["error"]["message"])
        conn.close.assert_called_once()

    def test_dispatch_proxy_suppresses_notification_response_on_connection_error(self):
        request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
        }
        conn = mock.Mock()
        conn.request.side_effect = ConnectionRefusedError("boom")

        with mock.patch.object(
            server.http.client,
            "HTTPConnection",
            return_value=conn,
        ):
            response = server.dispatch_proxy(request)

        self.assertIsNone(response)


class InstallMcpServerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)

    def _write_json(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _read_json(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_toml(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_install_mcp_servers_writes_each_supported_container_shape(self):
        cursor_path = self.root / "cursor" / "mcp.json"
        vscode_path = self.root / "vscode" / "settings.json"
        opencode_path = self.root / "opencode" / "opencode.json"
        codex_path = self.root / "codex" / "config.toml"

        self._write_json(
            cursor_path,
            {
                "mcpServers": {
                    "existing": {"keep": True},
                    "github.com/mrexodia/ida-pro-mcp": {"legacy": True},
                },
                "theme": "cursor",
            },
        )
        self._write_json(
            vscode_path,
            {
                "mcp": {"servers": {"existing": {"keep": True}}},
                "editor.tabSize": 4,
            },
        )
        self._write_json(
            opencode_path,
            {
                "mcp": {"existing": {"type": "remote", "url": "http://example/mcp"}},
                "theme": "midnight",
            },
        )
        self._write_toml(
            codex_path,
            """
[mcp_servers.existing]
url = "http://example/mcp"
""".strip(),
        )

        configs = {
            "Cursor": (str(cursor_path.parent), cursor_path.name),
            "VS Code": (str(vscode_path.parent), vscode_path.name),
            "Opencode": (str(opencode_path.parent), opencode_path.name),
            "Codex": (str(codex_path.parent), codex_path.name),
        }

        def fake_generate(*, client_name: str, transport: str) -> dict:
            return {"client": client_name, "transport": transport}

        with (
            mock.patch.object(server, "get_global_configs", return_value=configs),
            mock.patch.object(server, "generate_mcp_config", side_effect=fake_generate),
        ):
            server.install_mcp_servers(transport="streamable-http", quiet=True)

        cursor_config = self._read_json(cursor_path)
        self.assertEqual(cursor_config["theme"], "cursor")
        self.assertEqual(cursor_config["mcpServers"]["existing"], {"keep": True})
        self.assertEqual(
            cursor_config["mcpServers"][server.mcp.name],
            {"client": "Cursor", "transport": "streamable-http"},
        )
        self.assertNotIn("github.com/mrexodia/ida-pro-mcp", cursor_config["mcpServers"])

        vscode_config = self._read_json(vscode_path)
        self.assertEqual(vscode_config["editor.tabSize"], 4)
        self.assertEqual(vscode_config["mcp"]["servers"]["existing"], {"keep": True})
        self.assertEqual(
            vscode_config["mcp"]["servers"][server.mcp.name],
            {"client": "VS Code", "transport": "streamable-http"},
        )

        opencode_config = self._read_json(opencode_path)
        self.assertEqual(opencode_config["theme"], "midnight")
        self.assertEqual(
            opencode_config["mcp"]["existing"],
            {"type": "remote", "url": "http://example/mcp"},
        )
        self.assertEqual(
            opencode_config["mcp"][server.mcp.name],
            {"client": "Opencode", "transport": "streamable-http"},
        )

        with codex_path.open("rb") as handle:
            codex_config = tomllib.load(handle)
        self.assertEqual(
            codex_config["mcp_servers"][server.mcp.name],
            {"client": "Codex", "transport": "streamable-http"},
        )
        self.assertEqual(
            codex_config["mcp_servers"]["existing"],
            {"url": "http://example/mcp"},
        )

    def test_uninstall_mcp_servers_removes_only_target_server(self):
        cursor_path = self.root / "cursor" / "mcp.json"
        vscode_path = self.root / "vscode" / "settings.json"
        opencode_path = self.root / "opencode" / "opencode.json"
        codex_path = self.root / "codex" / "config.toml"

        self._write_json(
            cursor_path,
            {
                "mcpServers": {
                    "existing": {"keep": True},
                    server.mcp.name: {"remove": True},
                }
            },
        )
        self._write_json(
            vscode_path,
            {
                "mcp": {
                    "servers": {
                        "existing": {"keep": True},
                        server.mcp.name: {"remove": True},
                    }
                }
            },
        )
        self._write_json(
            opencode_path,
            {
                "mcp": {
                    "existing": {"keep": True},
                    server.mcp.name: {"remove": True},
                }
            },
        )
        self._write_toml(
            codex_path,
            f"""
[mcp_servers.existing]
url = "http://example/mcp"

[mcp_servers."{server.mcp.name}"]
command = "python"
""".strip(),
        )

        configs = {
            "Cursor": (str(cursor_path.parent), cursor_path.name),
            "VS Code": (str(vscode_path.parent), vscode_path.name),
            "Opencode": (str(opencode_path.parent), opencode_path.name),
            "Codex": (str(codex_path.parent), codex_path.name),
        }

        with mock.patch.object(server, "get_global_configs", return_value=configs):
            server.install_mcp_servers(uninstall=True, quiet=True)

        self.assertEqual(
            self._read_json(cursor_path)["mcpServers"],
            {"existing": {"keep": True}},
        )
        self.assertEqual(
            self._read_json(vscode_path)["mcp"]["servers"],
            {"existing": {"keep": True}},
        )
        self.assertEqual(
            self._read_json(opencode_path)["mcp"],
            {"existing": {"keep": True}},
        )
        with codex_path.open("rb") as handle:
            codex_config = tomllib.load(handle)
        self.assertEqual(
            codex_config["mcp_servers"],
            {"existing": {"url": "http://example/mcp"}},
        )

    def test_project_install_writes_root_level_opencode_file(self):
        project_dir = self.root / "project"
        project_dir.mkdir()

        with (
            mock.patch.object(
                server,
                "generate_mcp_config",
                return_value={"client": "Opencode", "transport": "stdio"},
            ),
            mock.patch.object(server.os, "getcwd", return_value=str(project_dir)),
        ):
            server.install_mcp_servers(project=True, quiet=True, only=["opencode"])

        config = self._read_json(project_dir / "opencode.json")
        self.assertEqual(
            config,
            {
                "mcp": {
                    server.mcp.name: {"client": "Opencode", "transport": "stdio"}
                }
            },
        )

    def test_is_client_installed_understands_opencode_top_level_mcp(self):
        config_dir = self.root / "opencode"
        config_dir.mkdir()
        config_path = config_dir / "opencode.json"
        self._write_json(config_path, {"mcp": {server.mcp.name: {"type": "local"}}})

        installed = server.is_client_installed(
            "Opencode",
            str(config_dir),
            "opencode.json",
        )

        self.assertTrue(installed)
