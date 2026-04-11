"""Tests for MCP protocol entrypoints and request dispatch."""

import json

from ..framework import assert_is_list, assert_non_empty, test
from ..rpc import MCP_SERVER


@test()
def test_mcp_initialize_dispatch_returns_server_capabilities():
    """initialize returns the advertised server metadata and discovery capabilities."""
    response = MCP_SERVER.registry.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }
    )

    assert response is not None
    result = response["result"]
    assert result["serverInfo"]["name"] == MCP_SERVER.name
    assert_non_empty(result["serverInfo"]["version"])
    assert "tools" in result["capabilities"]
    assert "resources" in result["capabilities"]
    assert "prompts" in result["capabilities"]


@test()
def test_mcp_resources_list_exposes_static_resources():
    """resources/list returns concrete browseable resources without template URIs."""
    result = MCP_SERVER._mcp_resources_list()
    assert_is_list(result["resources"], min_length=1)

    by_uri = {resource["uri"]: resource for resource in result["resources"]}
    assert "ida://idb/metadata" in by_uri
    assert "ida://idb/segments" in by_uri
    assert "ida://struct/{name}" not in by_uri


@test()
def test_mcp_resource_templates_list_exposes_parameterized_resources():
    """resources/templates/list returns URI templates and excludes concrete resources."""
    result = MCP_SERVER._mcp_resource_templates_list()
    assert_is_list(result["resourceTemplates"], min_length=1)

    by_uri = {template["uriTemplate"]: template for template in result["resourceTemplates"]}
    assert "ida://struct/{name}" in by_uri
    assert "ida://import/{name}" in by_uri
    assert "ida://idb/metadata" not in by_uri


@test(binary="crackme03.elf")
def test_mcp_resources_read_metadata_returns_json_contents():
    """resources/read wraps resource output as JSON content blocks."""
    result = MCP_SERVER._mcp_resources_read("ida://idb/metadata")
    assert result.get("isError") is not True
    assert_is_list(result["contents"], min_length=1)

    content = result["contents"][0]
    assert content["uri"] == "ida://idb/metadata"
    payload = json.loads(content["text"])
    assert_non_empty(payload["module"])
    assert_non_empty(payload["path"])
    assert_non_empty(payload["base"])


@test()
def test_mcp_tools_call_dispatch_wraps_success_result():
    """tools/call returns MCP content plus structuredContent for successful tools."""
    response = MCP_SERVER.registry.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "int_convert",
                "arguments": {"inputs": {"text": "0x41"}},
            },
        }
    )

    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert_is_list(result["content"], min_length=1)

    structured = result["structuredContent"]["result"]
    assert_is_list(structured, min_length=1)
    assert structured[0]["input"] == "0x41"
    assert structured[0]["result"]["decimal"] == "65"


@test()
def test_mcp_tools_call_dispatch_wraps_tool_lookup_errors():
    """tools/call surfaces missing-tool failures as MCP tool errors, not transport crashes."""
    response = MCP_SERVER.registry.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "__missing_tool__",
                "arguments": {},
            },
        }
    )

    assert response is not None
    result = response["result"]
    assert result["isError"] is True
    assert_is_list(result["content"], min_length=1)
    assert "Method '__missing_tool__' not found" in result["content"][0]["text"]
