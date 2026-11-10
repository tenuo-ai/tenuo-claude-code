"""Complete invocation binding and stable MCP server identities (no runtime I/O)."""
from __future__ import annotations
import json
import re


MCP_SERVER_NAME = "tenuo-files"


REQUEST_FIELD = "__tenuo_request"


def _validate_mcp_parts(server: str, tool: str) -> None:
    # Delimiter runs must have exactly two underscores. Otherwise the same
    # wire name can describe a different server/tool split on an external peer.
    if (not isinstance(server, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", server)
            or server.startswith("_") or server.endswith("_") or "__" in server):
        raise ValueError("MCP server names must not start/end with '_' or contain '__'")
    if (not isinstance(tool, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", tool)
            or tool.startswith("_") or "__" in tool):
        raise ValueError("MCP tool names must not start with '_' or contain '__'")


def validate_mcp_identity(name: str) -> None:
    """Reject ambiguous incoming/allow-listed names before any grant lookup."""
    parts = name.split("__")
    if len(parts) != 3 or parts[0].lower() != "mcp":
        raise ValueError("Invalid or ambiguous MCP identity")
    _validate_mcp_parts(parts[1], parts[2])


def mcp_server_name(cfg: dict) -> str:
    """One policy binds one unambiguous MCP server identity."""
    name = (cfg.get("mcp") or {}).get("server", MCP_SERVER_NAME)
    try:
        _validate_mcp_parts(name, "tool")
    except ValueError as exc:
        raise SystemExit(f"Invalid mcp.server: {exc}") from exc
    return name


def mcp_capability(cfg: dict, tool: str) -> str:
    server = mcp_server_name(cfg)
    try:
        _validate_mcp_parts(server, tool)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    return f"mcp__{server}__{tool}"


def bind_request(tool: str, tin: dict, args: dict) -> dict:
    """Bind the full invocation independently of the fields constrained by policy.

    Keep canonical JSON rather than a digest so approvers can inspect the exact
    operation covered by their signature. This reserved field is generated here,
    never trusted from tool input or a policy constraint.
    """
    request = json.dumps({"tool": tool, "arguments": tin or {}},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False)
    return {**args, REQUEST_FIELD: request}
