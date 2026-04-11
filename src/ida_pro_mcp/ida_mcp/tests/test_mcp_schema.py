"""Tests for MCP schema generation."""

from ..framework import test, assert_is_list
from ..rpc import MCP_SERVER


@test()
def test_mcp_tools_list_generates_registered_tool_schemas():
    """tools/list should introspect all registered tools without annotation errors."""
    result = MCP_SERVER._mcp_tools_list()
    assert_is_list(result["tools"], min_length=1)

    names = {tool["name"] for tool in result["tools"]}
    assert "set_comments" in names
    assert "make_data" in names
