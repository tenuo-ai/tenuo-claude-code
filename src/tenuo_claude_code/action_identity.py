"""Complete invocation binding and stable MCP server identities (no runtime I/O)."""
from __future__ import annotations
import json
import re


MCP_SERVER_NAME = "tenuo-files"


REQUEST_FIELD = "__tenuo_request"


def mcp_server_name(cfg: dict) -> str:
    """One policy binds one MCP server; the generated proxy has a stable default."""
    name = (cfg.get("mcp") or {}).get("server", MCP_SERVER_NAME)
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name) or "__" in name:
        raise SystemExit("mcp.server must be a server name containing letters, digits, '_' or '-'")
    return name


def mcp_capability(cfg: dict, tool: str) -> str:
    if not isinstance(tool, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", tool):
        raise SystemExit("MCP tool names must contain letters, digits, '_', '.' or '-'")
    return f"mcp__{mcp_server_name(cfg)}__{tool}"


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
