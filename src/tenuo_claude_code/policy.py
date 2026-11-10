"""Pure policy parsing and capability descriptions, independent of CLI state."""
from __future__ import annotations
from .action_identity import mcp_capability


# Claude tool -> (capability, primary arg, Claude input field for that arg)
#
# Command-execution tools (Bash, PowerShell, Monitor) all constrain a `command`
# string but each gets its OWN capability, not a shared `run_command`. Reasons:
#   - enforced_capabilities() de-dups capabilities first-wins, so a shared cap
#     would silently drop the second tool's constraint and check one shell's
#     command against another shell's policy.
#   - PowerShell is a different dialect from POSIX sh: prefer oneof/pattern/regex
#     over shlex for it. Separate caps let each tool carry its own constraint.
#   - Separate caps keep audit receipts unambiguous (which shell ran) and let an
#     operator allow one shell while denying another.
# All three are permission-required, side-effecting tools: never add them to the
# harness audit bundle. Govern them via `enforce` (or deny via the catch-all).
# The command-execution tool class: distinct shell front-ends over a `command`
# string. Each is an independent capability (see TOOL_DEFAULTS rationale above).


# Catch-all capability/tool names. "audit" is granted in the warrant (allow +
# log); "unlisted" is intentionally NOT granted, so routing to it yields a
# signed DENY receipt (used when default: deny).


TOOL_DEFAULTS = {
    "Read": ("read_file", "path", "file_path"),
    "Write": ("write_file", "path", "file_path"),
    "Edit": ("edit_file", "path", "file_path"),
    "Bash": ("run_command", "command", "command"),
    "PowerShell": ("run_powershell", "command", "command"),
    "Monitor": ("run_monitor", "command", "command"),
    "Glob": ("glob", "path", "path"),
    "Grep": ("grep", "path", "path"),
    "WebFetch": ("web_fetch", "url", "url"),
    "WebSearch": ("web_search", "query", "query"),
    "NotebookEdit": ("notebook_edit", "path", "notebook_path"),
}


COMMAND_EXEC_TOOLS = frozenset({"Bash", "PowerShell", "Monitor"})


_CAP_TO_CLAUDE = {cap: tool for tool, (cap, *_) in TOOL_DEFAULTS.items()}


def claude_tool_for_cap(cap: str) -> str:
    """Map a Tenuo capability back to the Claude tool name (fallback: cap)."""
    return _CAP_TO_CLAUDE.get(cap, cap)


CATCHALL_AUDIT = "audit"


CATCHALL_DENY = "unlisted"


def slug(name: str) -> str:
    return name.lower().replace("-", "_")


def audit_map(cfg: dict) -> dict:
    """Claude tool name -> capability name for the audit-allow list."""
    out = {}
    for tool in cfg.get("audit", []) or []:
        out[tool] = TOOL_DEFAULTS.get(tool, (slug(tool),))[0]
    return out


def default_mode(cfg: dict) -> str:
    """Fallback posture for tools in neither `enforce` nor `allow`.

    Canonical values: `deny` (block — the secure default) and `approve` (require
    human approval; Cloud-only). The legacy `audit`/`allow` (permit + log unlisted)
    is no longer supported — enforce must not fail open — and collapses to `deny`.
    """
    mode = (cfg.get("default") or "deny").strip().lower()
    return "approve" if mode == "approve" else "deny"


def catchall_cap(cfg: dict) -> str:
    """Capability the /gate catch-all routes to.

    `default: approve` -> the 'audit' cap, which the Cloud trigger warrant grants
    WITH an approval gate, so an unlisted tool pauses for human sign-off. (Local
    warrants never grant it, so locally `approve` falls back to deny.) Otherwise
    the ungranted 'unlisted' cap -> the authorizer returns a signed DENY.
    """
    return CATCHALL_AUDIT if default_mode(cfg) == "approve" else CATCHALL_DENY


def subagent_roles(cfg: dict) -> dict:
    """Declared subagent roles (name -> {tools, ttl_seconds, ...}); {} when none."""
    return cfg.get("subagents") or {}


DEFAULT_SESSION_TTL_SECONDS = 3600


def session_ttl_seconds(cfg: dict) -> int:
    """Session warrant lifetime in seconds from `ttl_seconds`, else the default (1h).

    Single source of truth for both mint paths — local mint (`mint_local_warrant`)
    and the Cloud trigger config (`admin.build_warrant_config`). Validated in
    `validate_ttl_seconds` at load time, so by the time this runs the value is a
    positive int; the bounds check here is defensive (e.g. an in-memory cfg that
    skipped load_config).
    """
    raw = cfg.get("ttl_seconds")
    if raw is None:
        return DEFAULT_SESSION_TTL_SECONDS
    return validate_ttl_seconds(raw)


def validate_ttl_seconds(raw) -> int:
    """Coerce + validate a session `ttl_seconds` value; must be a positive integer.

    Rejects bools (a YAML `true`/`false` is not a duration), non-integers, and
    non-positive values with the tool's usual `SystemExit` error style. Mirrors how
    `_normalize_posture_keys` fails loud on a bad `mode`/`default`."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise SystemExit(
            f"Invalid ttl_seconds: {raw!r}. Must be a positive integer (seconds).")
    if raw <= 0:
        raise SystemExit(
            f"Invalid ttl_seconds: {raw}. Must be a positive integer (seconds).")
    return raw


def webfetch_approval(cfg: dict) -> dict | None:
    """`enforce.WebFetch.approval` block if declared, else None (Cloud human-approval gate)."""
    wf = (cfg.get("enforce") or {}).get("WebFetch")
    if isinstance(wf, dict) and isinstance(wf.get("approval"), dict):
        return wf["approval"]
    return None


MCP_ARG_FIELD = {
    "read_file": "path",
    "list_directory": "path",
    "delete_deployment": "target",
}


_MCP_SPEC_KEYS = frozenset({"arg", "args", "constraint", "approval", "exempt"})


def _mcp_constraints_from_spec(raw: dict) -> dict:
    """Extract {arg: constraint_spec} from a structured mcp.enforce entry.

    Forms (mutually exclusive; unknown/conflicting keys are rejected, not
    silently resolved):
      {args: {<arg>: "<spec>", ...}}        -> constrain several named arguments
      {arg: <name>, constraint: "<spec>"}   -> constrain one named argument
      {constraint: "<spec>"}                -> constrain the default (`path`) arg
    """
    if "path" in raw:
        raise SystemExit(
            "mcp.enforce: `path:` is not a key; use `constraint:` for the path arg, "
            "or `arg: <name>` + `constraint:` to constrain a different argument")
    unknown = set(raw) - _MCP_SPEC_KEYS
    if unknown:
        raise SystemExit(
            f"mcp.enforce: unknown key(s) {sorted(unknown)}; expected any of "
            f"{sorted(_MCP_SPEC_KEYS)}")
    has_args, has_arg, has_constraint = "args" in raw, "arg" in raw, "constraint" in raw
    if has_args and (has_arg or has_constraint):
        raise SystemExit("mcp.enforce: use either `args:` or `arg:`/`constraint:`, not both")
    if has_args:
        args = raw["args"]
        if not isinstance(args, dict) or not args:
            raise SystemExit(
                f"mcp.enforce `args:` must be a non-empty map of arg->constraint, got {args!r}")
        out = {}
        for a, s in args.items():
            key = str(a)
            if not key.strip():
                raise SystemExit("mcp.enforce `args:` argument name cannot be empty")
            if not isinstance(s, str):
                raise SystemExit(f"mcp.enforce `args.{a}` must be a constraint string, got {s!r}")
            out[key] = s
        return out
    if has_arg:
        key = str(raw["arg"])
        if not key.strip():
            raise SystemExit("mcp.enforce `arg:` name cannot be empty")
        spec = raw.get("constraint")
        if not isinstance(spec, str):
            raise SystemExit("mcp.enforce: `arg:` needs a `constraint:` string")
        return {key: spec}
    if has_constraint:
        spec = raw["constraint"]
        if not isinstance(spec, str):
            raise SystemExit(f"mcp.enforce `constraint:` must be a string, got {spec!r}")
        return {"path": spec}
    return {}


def parse_mcp_enforce_spec(spec) -> dict:
    """Parse one ``mcp.enforce`` entry into named-arg constraints + approval.

    Returns ``{"constraints": {arg: spec_str}, "approval": dict|None,
    "exempt_args": {arg: spec_str}|None}``. A bare string constrains the `path`
    argument (back-compat); `arg:`/`args:` name any other argument(s).
    """
    if isinstance(spec, str):
        return {"constraints": {"path": spec}, "approval": None, "exempt_args": None}
    if not isinstance(spec, dict):
        raise SystemExit(f"Invalid mcp.enforce value: {spec!r}")
    raw = dict(spec)
    approval = raw.get("approval")
    if approval is not None and not isinstance(approval, dict):
        raise SystemExit(f"Invalid mcp.enforce approval block: {approval!r}")
    for value in (raw.get("exempt"), (approval or {}).get("exempt")):
        if value is not None and (not isinstance(value, dict) or
                any(not isinstance(k, str) or not k.strip() or not isinstance(v, str)
                    for k, v in value.items())):
            raise SystemExit("mcp.enforce exemptions must map argument names to constraint strings")
    exempt_args = None
    if isinstance(approval, dict) and isinstance(approval.get("exempt"), dict):
        exempt_args = approval["exempt"]
        approval = {k: v for k, v in approval.items() if k != "exempt"}
    if isinstance(raw.get("exempt"), dict):
        exempt_args = raw["exempt"]
    constraints = _mcp_constraints_from_spec(raw)
    if not constraints and not approval:
        raise SystemExit(
            f"Invalid mcp.enforce entry {raw!r}: need a constraint string, an "
            "`arg`/`args` constraint, or an approval block")
    return {"constraints": constraints, "approval": approval, "exempt_args": exempt_args}


def mcp_enforce_entries(cfg: dict) -> dict[str, dict]:
    return {
        tool: parse_mcp_enforce_spec(spec)
        for tool, spec in ((cfg.get("mcp") or {}).get("enforce") or {}).items()
    }


def mcp_default_arg(tool: str) -> str:
    """The constrained arg to assume when a policy doesn't name one."""
    return MCP_ARG_FIELD.get(tool, "path")


def mcp_constraint_args(tool: str, parsed: dict) -> dict:
    """arg name -> constraint spec string (``None`` = approval-gated wildcard arg).

    Concrete constraints win; an approval gate only relaxes its arg(s) to
    wildcards when there are no concrete constraints. The gated args are the
    `exempt:` keys, or the tool's default arg when no exemptions are declared.
    """
    cons = parsed.get("constraints") or {}
    if cons:
        return dict(cons)
    if parsed.get("approval"):
        gated = list((parsed.get("exempt_args") or {}).keys()) or [mcp_default_arg(tool)]
        return {a: None for a in gated}
    return {}


def approval_entries(cfg: dict) -> list[tuple[str, dict]]:
    """(authorizer capability, approval settings) for every gated tool.

    Includes the catch-all when `default: approve` so `tenuo-admin setup` creates
    the session approval policy and the hook budget accounts for the wait.
    """
    entries: list[tuple[str, dict]] = []
    if appr := webfetch_approval(cfg):
        entries.append(("web_fetch", appr))
    for g in governed_map(cfg).values():
        if g.get("approval"):           # native enforce tool with an approval block
            entries.append((g["cap"], g["approval"]))
    for tool, parsed in mcp_enforce_entries(cfg).items():
        if parsed.get("approval"):
            entries.append((mcp_capability(cfg, tool), parsed["approval"]))
    if default_mode(cfg) == "approve":
        entries.append((CATCHALL_AUDIT, {"threshold": 1}))
    return entries


def has_approval_gates(cfg: dict) -> bool:
    return bool(approval_entries(cfg))


MODE_ENFORCE = "enforce"


MODE_DRY_RUN = "dry-run"


_OBSERVE_ALIASES = {"dry-run", "dry_run", "dryrun", "audit"}


def policy_mode(cfg: dict) -> str:
    """Canonical posture: ``MODE_ENFORCE`` or ``MODE_DRY_RUN``.

    Recognizes the canonical ``dry-run`` plus the deprecated ``audit`` alias (and a
    couple of forgiving spellings). Anything else — including a typo or a value
    like ``allow`` that belongs on ``default:`` — canonicalizes to ``enforce``
    (fail-closed), but `posture_warnings` surfaces it so it can't fail silently.
    """
    raw = str(cfg.get("mode", MODE_ENFORCE)).strip().lower()
    if raw in _OBSERVE_ALIASES:
        return MODE_DRY_RUN
    return MODE_ENFORCE


def _normalize_posture_keys(cfg: dict) -> list[str]:
    """Canonicalize `mode`/`default` in-place; return deprecation notices.

    `mode: audit` -> dry-run; `default: audit|allow` -> deny (enforce must not fail
    open). Unknown values fail loud. Returned strings are surfaced from user-facing
    commands (check/refresh/status), never the hook hot path.
    """
    deps: list[str] = []
    raw_mode = str(cfg.get("mode", "enforce")).strip().lower()
    if raw_mode == "audit":
        deps.append("`mode: audit` is deprecated — rename to `mode: dry-run`")
    elif raw_mode not in ("enforce", "dry-run", "dry_run", "dryrun"):
        raise SystemExit(f"Unknown mode: '{raw_mode}'. Valid: enforce, dry-run.")
    raw_default = (cfg.get("default") or "deny").strip().lower()
    if raw_default in ("audit", "allow"):
        deps.append(
            f"`default: {raw_default}` is no longer supported — enforce must not "
            "fail open. Unlisted tools are now DENIED. Use `mode: dry-run` to "
            "observe, or add specific tools to `allow:`.")
        cfg["default"] = "deny"
    elif raw_default not in ("deny", "approve"):
        raise SystemExit(f"Unknown default: '{raw_default}'. Valid: deny, approve.")
    return deps


def governed_map(cfg: dict) -> dict:
    """Claude tool -> dict(capability, arg, field, + constraint spec / web policy / approval).

    A native value is a constraint string, or a dict: `WebFetch` takes a web policy
    (domains/cidrs/approval); any other tool takes an `approval:` block (with an
    optional `exempt:` constraint string on its arg) for a Cloud human-approval gate
    — e.g. `Bash: {approval: {threshold: 1, exempt: "shlex:ls,pwd"}}`.
    """
    out = {}
    for tool, spec in (cfg.get("enforce") or {}).items():
        if tool not in TOOL_DEFAULTS:
            raise SystemExit(f"enforce: unknown tool '{tool}'")
        cap, arg, field = TOOL_DEFAULTS[tool]
        if isinstance(spec, dict):
            if tool == "WebFetch":
                out[tool] = {"cap": cap, "arg": arg, "field": field, "web": spec}
            elif isinstance(spec.get("approval"), dict):
                appr = dict(spec["approval"])
                exempt = appr.pop("exempt", None)   # constraint spec (string) on this tool's arg
                if exempt is not None and not isinstance(exempt, str):
                    raise SystemExit(f"enforce.{tool}.approval.exempt must be a constraint string")
                out[tool] = {"cap": cap, "arg": arg, "field": field,
                             "approval": appr, "exempt": exempt}
            else:
                raise SystemExit(
                    f"enforce.{tool}: a structured value needs an `approval:` block "
                    "(only WebFetch takes domains/cidrs).")
        else:
            out[tool] = {"cap": cap, "arg": arg, "field": field, "spec": spec}
    return out
