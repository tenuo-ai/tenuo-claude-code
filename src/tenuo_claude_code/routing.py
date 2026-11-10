"""Translate tool calls into signed authorization requests without performing I/O."""
from __future__ import annotations
import os
import urllib.parse
from .action_identity import bind_request, mcp_capability
from .policy import governed_map, audit_map, mcp_enforce_entries, mcp_constraint_args, default_mode, catchall_cap


def mcp_tool_name(tool_name: str) -> str | None:
    """Bare MCP tool from a Claude MCP call name, else None.

    Claude exposes proxied MCP tools as `mcp__<server>__<tool>` and fires the
    PreToolUse hook on that prefixed name. We strip to the bare `<tool>` so the
    hook can enforce it against the SAME `mcp.enforce` policy the proxy uses —
    otherwise the prefixed name matches nothing and catch-all default-denies even
    allowed MCP tools, shadowing the proxy. `<tool>` may contain underscores; the
    `__` delimiter is double, so split(maxsplit=2) keeps it intact.
    """
    if not tool_name.startswith("mcp__"):
        return None
    parts = tool_name.split("__", 2)
    return parts[2] if len(parts) == 3 and parts[2] else None


def resolve_tool(cfg: dict, tool_name: str, tool_input: dict):
    """Map a Claude tool call to (tenuo_tool, route, sign_args, body, governed).

    - enforced native tools: real constraints (may mutate within scope).
    - enforced MCP tools (bare downstream name or `mcp__<server>__<tool>` from the
      hook): same policy/route the proxy uses, so hook and proxy agree.
    - audit-listed tools: allowed + logged (no constraints).
    - everything else: catch-all. With default: deny it routes to a capability
      the warrant does NOT grant, so the authorizer returns a signed DENY.
    """
    gov = governed_map(cfg)
    if tool_name in gov:
        g = gov[tool_name]
        val = (tool_input or {}).get(g["field"])
        if "web" in g:
            url = val if isinstance(val, str) else ""
            try:
                host = urllib.parse.urlsplit(url).hostname or ""
            except ValueError:
                host = ""
            args = {"url": url, "host": host}
        else:
            if g.get("spec", "").startswith("subpath:"):
                # Tools like Glob/Grep default their search root to the cwd;
                # authorize what would actually be touched, not a blank.
                if not (isinstance(val, str) and val):
                    val = os.getcwd()
                # Resolve symlinks so a link inside the sandbox can't point
                # the Territory outside the Map we check (realpath ~= Layer 2
                # for pre-existing links; races still need path_jail).
                val = os.path.realpath(os.path.abspath(val))
            args = {g["arg"]: val}
        args = bind_request(tool_name, tool_input, args)
        return g["cap"], f"/verify/{g['cap']}", args, args, True

    audit = audit_map(cfg)
    if tool_name in audit:
        cap = audit[tool_name]
        return cap, f"/verify/{cap}", {}, dict(tool_input or {}), False

    mcp_enforce = mcp_enforce_entries(cfg)
    bare = mcp_tool_name(tool_name)
    if bare is not None and tool_name != mcp_capability(cfg, bare):
        # A same-named tool on another server is not this policy's capability.
        bare = None
    if not tool_name.startswith("mcp__") and bare is None and tool_name in mcp_enforce:
        bare = tool_name
    if bare is not None and bare in mcp_enforce:
        parsed = mcp_enforce[bare]
        args = {}
        for field, spec in mcp_constraint_args(bare, parsed).items():
            val = (tool_input or {}).get(field)
            # Canonicalize symlinks only for path-scoped (subpath) args, so the
            # Territory we check matches the Map; never rewrite non-path values.
            if isinstance(spec, str) and spec.startswith("subpath:") \
                    and isinstance(val, str) and val:
                val = os.path.realpath(os.path.abspath(val))
            args[field] = val
        cap = mcp_capability(cfg, bare)
        args = bind_request(cap, tool_input, args)
        return cap, f"/verify/{cap}", args, args, True

    # Catch-all. Under `default: approve` the catch-all carries a whole-tool gate
    # (every unlisted call requires approval), so we don't need to sign `tool` to
    # make the gate fire. We sign it anyway so the approval's request_hash binds per
    # tool name — approving one unlisted tool must not auto-approve another — and the
    # signed args must match what the /gate route extracts. Under `deny` the cap is
    # ungranted, so no args are checked (route extracts none) — keep sign_args empty.
    if default_mode(cfg) == "approve":
        args = bind_request(tool_name, tool_input, {"tool": tool_name})
        return catchall_cap(cfg), "/gate", args, args, False
    return catchall_cap(cfg), "/gate", {}, {"tool": tool_name, **(tool_input or {})}, False


def explicitly_denied(cfg: dict, tool: str) -> bool:
    """True for a tool the policy lists under `deny:` (by its Claude or bare MCP name).

    Decided before routing, so no fallback posture (`default: approve`) applies.
    """
    denied = cfg.get("_deny") or ()
    return tool in denied or (mcp_tool_name(tool) or tool) in denied
