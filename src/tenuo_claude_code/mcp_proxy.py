"""Stdio MCP adapter. Runtime services are supplied explicitly by the CLI."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from .action_identity import mcp_capability, mcp_server_name


@dataclass(frozen=True)
class ProxyContext:
    DEMO_DIR: Path
    load_config: Callable[[], dict]
    apply_transport_env: Callable[[dict], None]
    downstream_server: Callable[[dict], tuple]
    is_dry_run_mode: Callable[[dict], bool]
    subagent_roles: Callable[[dict], dict]
    follow_moved_state: Callable[[], bool]
    authorize_call: Callable[..., tuple]
    write_receipt: Callable[[dict], bool]
    mcp_proxy_decision: Callable[..., tuple]


def serve(context: ProxyContext) -> None:
    import asyncio

    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import CallToolResult, TextContent

    cfg = context.load_config()
    context.apply_transport_env(cfg)
    mcp_cfg = cfg.get("mcp", {})
    command, command_args, env, downstream = context.downstream_server(mcp_cfg)
    initial_server = mcp_server_name(cfg)
    initial_transport = {k: (cfg.get("authorizer") or {}).get(k) for k in ("transport", "socket")}

    def log(m):
        print(f"[tenuo-mcp-proxy] {m}", file=sys.stderr, flush=True)

    async def run():
        params = StdioServerParameters(command=command, args=command_args, env=env, cwd=str(context.DEMO_DIR))
        async with stdio_client(params) as (dr, dw):
            async with ClientSession(dr, dw) as down:
                await down.initialize()
                log(f"connected to {downstream}")
                proxy = Server("tenuo-mcp-proxy")

                @proxy.list_tools()
                async def _lt():
                    return (await down.list_tools()).tools

                @proxy.call_tool()
                async def _ct(name: str, arguments: dict):
                    # HiTL note: context.authorize_call routes governed calls through
                    # authorize_with_approval, so when the warrant carries an
                    # approval gate this BLOCKS on the Cloud approval poll (in a
                    # worker thread) and returns the approver's decision. The
                    # downstream forward below runs only AFTER that resolves and
                    # only while this call is still open — if the client cancels
                    # (its tool timeout), the await is cancelled and we never
                    # forward, so an approved-but-abandoned call does not execute.
                    # (Forwarding is what's cancellation-safe; the to_thread worker
                    # running the poll can't be killed and keeps polling/writing its
                    # receipt in the background until its own timeout — its result is
                    # just discarded.)
                    tin = dict(arguments or {})
                    context.follow_moved_state()
                    try:
                        current = context.load_config()
                        transport = {k: (current.get("authorizer") or {}).get(k) for k in ("transport", "socket")}
                        if (context.downstream_server(current.get("mcp", {}))[:3] != (command, command_args, env)
                                or mcp_server_name(current) != initial_server or transport != initial_transport):
                            raise ValueError("MCP server or transport changed; reconnect the MCP client")
                        observe = context.is_dry_run_mode(current)
                        current_roles = context.subagent_roles(current)
                    except (Exception, SystemExit) as exc:
                        context.write_receipt({"phase": "pre", "source": "mcp_proxy", "decision": "deny",
                                       "claude_tool": name, "args": tin, "reason": str(exc)})
                        return CallToolResult(content=[TextContent(type="text", text=f"Tenuo policy unavailable: {exc}")], isError=True)
                    allowed, reason, _, tenuo_tool, authz_evidence = await asyncio.to_thread(
                        context.authorize_call, current, mcp_capability(current, name), tin, None, current_roles,
                        live=not observe, return_context=True)
                    wrote = context.write_receipt({"phase": "pre", "source": "mcp_proxy",
                                   "decision": "allow" if allowed else "deny",
                                   "shadow": observe, "claude_tool": name,
                                   "tenuo_tool": tenuo_tool,
                                   "args": tin, "reason": reason,
                                   "authz": authz_evidence})
                    # strict_receipts: don't forward an allowed call we couldn't log.
                    if allowed and not observe and not wrote and current.get("strict_receipts"):
                        allowed, reason = False, "audit receipt unwritable, strict_receipts on (fail-closed)"
                    forward, message = context.mcp_proxy_decision(allowed, reason, observe, name)
                    if not forward:
                        log(f"DENY {name}: {reason}")
                        return CallToolResult(content=[TextContent(type="text", text=message)], isError=True)
                    if not allowed:
                        log(f"WOULD-DENY {name} (observe-only, forwarding): {reason}")
                    # Pass the server's result through whole, so its own isError
                    # and structured content reach the client.
                    return await down.call_tool(name, tin)

                async with stdio_server() as (r, w):
                    await proxy.run(r, w, proxy.create_initialization_options())

    asyncio.run(run())

