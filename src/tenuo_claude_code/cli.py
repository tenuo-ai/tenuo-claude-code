#!/usr/bin/env python3
"""tenuo-claude — govern, enforce, and audit Claude Code with Tenuo.

One CLI driven by one policy file (tenuo.yaml in your project directory). It
generates the warrant, gateway config, Claude hooks, and MCP proxy wiring so
nothing drifts, and manages the Cloud-connected authorizer lifecycle.

Install: ``pip install tenuo-claude-code``  (command: ``tenuo-claude``)

    tenuo-claude init      # generate keys, warrant, gateway, Claude hooks
    tenuo-claude bootstrap # example policy + init + up + verify (fresh folder)
    tenuo-claude refresh   # re-apply tenuo.yaml after policy edits
    tenuo-claude up        # start the authorizer (+ connect Cloud if configured)
    tenuo-claude status    # warrant / authorizer / Cloud / policy summary
    tenuo-claude check     # preflight: deps, credentials, wiring drift
    tenuo-claude verify    # policy self-test against the authorizer
    tenuo-claude demo      # scripted tour (tenuo_demo.py in project, if present)
    tenuo-claude bench     # per-tool-call overhead (authorizer + hooks)

Internal entrypoints (wired into Claude, not called by hand):
    _hook  _post  _mcp-proxy

Optional scripted tour: ``tenuo_demo.py`` in your project directory (see repo ``demo/``).
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl  # POSIX advisory file locking (macOS/Linux)
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

from tenuo_claude_code import __version__, authorizer_runtime as art
from tenuo_claude_code.paths import (
    ADMIN_COMMAND,
    ADMIN_COMMAND_LEGACY,
    BIN_LAUNCHER,
    CLI_COMMAND,
    CLI_COMMAND_LEGACY,
    bind_project_paths,
    scaffold_example_policy,
)
from tenuo_claude_code import packs
from tenuo_claude_code.verify import ProbeResult, build_probes, format_text, run_probes

# ---------------------------------------------------------------------------
# Paths & constants (bound to project root via bind_project_paths() at startup)
# ---------------------------------------------------------------------------

DEMO_DIR: Path
STATE: Path
CONFIG_FILE: Path
CLOUD_PROFILE: Path
ADVANCED_PROFILE: Path
CLOUD_ENV_EXAMPLE: Path
HARNESS_TOOLS_FILE: Path
AGENTS_DIRS: tuple
LAUNCHER: Path
LAUNCHER_REL: str
MCP_SERVER_NAME = "tenuo-files"
HOLDER_KEY: Path
ISSUER_KEY: Path
ISSUER_PUB: Path
RECEIPT_KEY: Path
RECEIPT_PUB: Path
WARRANT: Path
STATE_JSON: Path
GATEWAY: Path
SRL: Path
RECEIPTS: Path
CLOUD_ENV: Path
CLOUD_STATE: Path

ADMIN_ENV = Path.home() / ".tenuo" / "admin.env"
_receipt_write_warned = False  # one-time stderr if .state/receipts.jsonl can't be written

PORT = art.resolve_authorizer_port()
AUTHZ_URL = f"http://127.0.0.1:{PORT}"

# Default path for the Unix-socket transport (see `authz_endpoint`). A root-owned
# socket under a root-owned, non-world-writable runtime dir is what lets the hook
# AUTHENTICATE the authorizer by OS file ownership — something loopback TCP cannot
# do. The path itself isn't a secret; the safety comes from `_safe_managed_socket`.
DEFAULT_AUTHZ_SOCKET = "/var/run/tenuo/authorizer.sock"
# Root-owned marker that lets a managed deployment fall back to loopback TCP (see
# `_insecure_tcp_breakglass`). Deliberately a file under an admin-only dir, not an
# env var, so a local user can't re-enable the TCP downgrade.
BREAKGLASS_TCP_FILE = "/etc/tenuo/allow_insecure_tcp"


def _decode_b64url_or_standard(value: str) -> bytes:
    """Decode Tenuo header base64, accepting URL-safe no-pad and standard forms."""
    token = "".join(value.split())
    padded = token + ("=" * ((4 - len(token) % 4) % 4))
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return base64.b64decode(padded)


def _decode_warrant_header(value: str):
    """Decode a header carrying either a WarrantStack or one bare warrant."""
    from tenuo import Warrant
    from tenuo_core import decode_warrant_stack_base64

    try:
        return decode_warrant_stack_base64(value)
    except Exception:
        return [Warrant.from_base64(value)]


def resolve_authz_url() -> str:
    """Loopback TCP URL for authorizer client calls. ``state.json`` overrides port env vars.

    This is only the TCP arm of the transport: `authz_endpoint` decides whether a call
    goes over a Unix socket or TCP, and managed mode normally uses a Unix socket (see
    below), calling this only for the TCP break-glass path.

    EXCEPTION: under the MDM-pinned managed hook the ``state.json`` override is ignored.
    It lives in an editable project file (`.state/state.json`), so honoring it would let
    a developer redirect the managed hook to a user-controlled authorizer. Managed TCP
    calls always target the pinned loopback address.

    NOTE (residual): loopback TCP cannot AUTHENTICATE the responder — if the system
    authorizer is down, a user process could bind the same 127.0.0.1 port and answer
    "allow". That is why managed mode defaults to the Unix-socket transport
    (`authz_endpoint` / TENUO_AUTHZ_SOCKET) and only falls back to TCP via the
    root-owned break-glass: a root-owned socket under a root-owned runtime dir can't be
    replaced by an unprivileged user, and `_safe_managed_socket` refuses anything that
    doesn't meet those ownership/permission invariants.
    """
    if not _managed_enforce_pinned():
        try:
            if STATE_JSON.is_file():
                url = json.loads(STATE_JSON.read_text()).get("authorizer_url")
                if isinstance(url, str) and url.startswith("http"):
                    return url
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
    return AUTHZ_URL


def _insecure_tcp_breakglass() -> bool:
    """True only when a ROOT-OWNED break-glass marker opts a managed deployment back
    onto loopback TCP (e.g. mid-migration, before the socket authorizer is live).

    It is a root-owned file, NOT an env var, on purpose: the managed hook inherits
    the user's environment, so an env-based escape would let any local user re-enable
    the unauthenticated-TCP downgrade and defeat the whole point. Only an admin who
    can write under ``/etc/tenuo`` can flip this. Non-POSIX has no ownership model,
    so the marker's mere presence counts there.

    Because this intentionally reopens the dangerous transport, the checks are strict
    (mirroring `_safe_managed_socket`): the marker must be a REGULAR file (not a
    symlink — else a user could point it at any root-owned file like /etc/hosts and
    `stat` would follow it), root-owned, not group/world-writable, under a root-owned,
    non-world-writable directory. Anything else is treated as "no break-glass".
    """
    if os.name != "posix":
        return os.path.exists(BREAKGLASS_TCP_FILE)
    import stat as _stat

    try:
        st = os.lstat(BREAKGLASS_TCP_FILE)
    except OSError:
        return False
    if _stat.S_ISLNK(st.st_mode) or not _stat.S_ISREG(st.st_mode):
        return False
    if st.st_uid != 0 or (st.st_mode & 0o022):
        return False
    parent = os.path.dirname(BREAKGLASS_TCP_FILE) or "/"
    try:
        dst = os.stat(parent)
    except OSError:
        return False
    return dst.st_uid == 0 and not (dst.st_mode & 0o022)


def authz_endpoint() -> tuple[str, str]:
    """Resolve how the client reaches the authorizer: ``("unix", socket_path)`` or
    ``("tcp", url)``.

    Driven by environment so the per-call enforcement path stays config-free; the
    process entrypoints (`cmd_hook`, `cmd_mcp_proxy`) seed these from `tenuo.yaml`
    via `apply_transport_env`:

      - ``TENUO_AUTHZ_TRANSPORT``  : ``unix`` | ``tcp``
      - ``TENUO_AUTHZ_SOCKET``     : socket path (implies unix unless transport=tcp)

    MANAGED (``_managed_enforce_pinned``): the authorizer must be reached over an
    OS-authenticated Unix socket, FULL STOP. Inherited environment is NOT trusted to
    pick the transport here — Claude runs hook commands with the user's environment,
    so honoring ``TENUO_AUTHZ_TRANSPORT=tcp`` would let any local user put managed
    enforcement back on unauthenticated loopback TCP (where a process that wins the
    port race can answer "allow"). So managed always selects unix and ignores an
    inherited ``tcp``; the only way back to TCP is the root-owned break-glass. The
    socket PATH may still come from the environment because `_safe_managed_socket`
    independently rejects any socket a non-root user could have created — a hostile
    path simply fails closed.

    UNMANAGED: the socket transport is strictly opt-in (explicit ``unix``, or a
    socket path without an explicit ``tcp``); otherwise loopback TCP, unchanged.
    """
    transport = os.environ.get("TENUO_AUTHZ_TRANSPORT", "").strip().lower()
    sock = os.environ.get("TENUO_AUTHZ_SOCKET", "").strip()
    if _managed_enforce_pinned():
        if _insecure_tcp_breakglass():
            return ("tcp", resolve_authz_url())
        return ("unix", sock or DEFAULT_AUTHZ_SOCKET)
    if transport == "unix" or (sock and transport != "tcp"):
        return ("unix", sock or DEFAULT_AUTHZ_SOCKET)
    return ("tcp", resolve_authz_url())


def authz_display() -> str:
    """Human-readable authorizer endpoint for status/verify output, reflecting the
    transport actually in use (so a managed socket deployment doesn't misreport the
    old loopback TCP URL)."""
    mode, loc = authz_endpoint()
    return loc if mode == "tcp" else f"unix://{loc}"


def apply_transport_env(cfg: dict) -> None:
    """Seed the transport env from ``authorizer.transport`` / ``authorizer.socket``
    in tenuo.yaml, once per process, WITHOUT clobbering anything already set.

    This ONLY configures the UNMANAGED (dev) opt-in. In managed mode it is a no-op:
    the editable policy file is not trusted to choose the transport OR the socket
    path, so a developer cannot repoint the pinned managed hook at all (not even to a
    bogus socket that would silently turn enforcement into deny-all). Managed mode
    instead uses `DEFAULT_AUTHZ_SOCKET` (or a `TENUO_AUTHZ_SOCKET` set by the
    developer-unwritable MDM hook command), and `_safe_managed_socket` is the backstop.
    """
    if _managed_enforce_pinned():
        return
    az = cfg.get("authorizer")
    if not isinstance(az, dict):
        return
    if "TENUO_AUTHZ_TRANSPORT" not in os.environ and az.get("transport"):
        os.environ["TENUO_AUTHZ_TRANSPORT"] = str(az["transport"]).strip().lower()
    if "TENUO_AUTHZ_SOCKET" not in os.environ and az.get("socket"):
        os.environ["TENUO_AUTHZ_SOCKET"] = str(az["socket"]).strip()


def _safe_managed_socket(path: str, *, managed: bool = True) -> tuple[bool, str]:
    """Verify a Unix authorizer socket is one only a trusted process could have
    created, so its decisions can be trusted. Returns ``(ok, reason)``.

    This is the authentication loopback TCP lacks: instead of a secret, we rely on
    OS file ownership. Nobody outside the trusted set can create or replace a socket
    inside a directory owned by the trusted set and not group/world-writable, so if
    the socket and its parent dir pass these checks, the responder is the trusted
    service — not a process that won a port race. Invariants:

      - the socket exists, is a socket, and is NOT a symlink (no redirect tricks);
      - the socket is owned by a trusted uid;
      - the parent dir is owned by a trusted uid and is not group/world-writable.

    The trusted set depends on the threat model. ``managed=True`` (the pinned hook,
    where the developer is the adversary) trusts ROOT only — plus an optional
    ``TENUO_AUTHZ_SERVICE_UID`` for a non-root service user. ``managed=False`` (a
    cooperative dev running their own authorizer) also trusts the CALLING user, so
    the opt-in dev socket actually works without running as root.

    POSIX only — uid/mode semantics don't apply elsewhere; callers fail closed when
    `os.name != "posix"`.
    """
    import stat as _stat

    sock_uids = {0}
    dir_uids = {0}
    svc = os.environ.get("TENUO_AUTHZ_SERVICE_UID", "").strip()
    if svc.isdigit():
        sock_uids.add(int(svc))
    if not managed:
        # Cooperative dev: a socket the developer owns (in a dir they own) is fine;
        # there is no privilege boundary to cross. World/group-writable is still out.
        me = os.getuid()
        sock_uids.add(me)
        dir_uids.add(me)
    try:
        st = os.lstat(path)
    except OSError as exc:
        return False, f"socket unavailable ({exc.strerror or exc})"
    if _stat.S_ISLNK(st.st_mode):
        return False, "socket path is a symlink"
    if not _stat.S_ISSOCK(st.st_mode):
        return False, "path is not a socket"
    if st.st_uid not in sock_uids:
        return False, f"socket owned by uid {st.st_uid}, not trusted (root/service)"
    parent = os.path.dirname(os.path.realpath(path)) or "/"
    try:
        dst = os.stat(parent)
    except OSError as exc:
        return False, f"socket dir unavailable ({exc.strerror or exc})"
    if dst.st_uid not in dir_uids:
        return False, f"socket dir {parent} not trusted-owned (uid {dst.st_uid})"
    if dst.st_mode & 0o022:
        return False, f"socket dir {parent} is group/world-writable"
    return True, "ok"


class _UDSConnection:
    """Minimal HTTP/1.1-over-Unix-socket client. The authorizer speaks the same
    HTTP API on a socket as on TCP, so we reuse `http.client` with an AF_UNIX
    connection rather than introducing a second request format."""

    def __init__(self, socket_path: str, timeout: float):
        import http.client

        self._path = socket_path
        self._conn = http.client.HTTPConnection("localhost", timeout=timeout)
        self._conn.connect = self._connect  # type: ignore[method-assign]

    def _connect(self) -> None:
        import socket as _socket

        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.settimeout(self._conn.timeout)
        s.connect(self._path)
        self._conn.sock = s

    def request(self, method: str, route: str, headers: dict | None = None,
                data: bytes | None = None) -> tuple[int, bytes]:
        try:
            self._conn.request(method, route, body=data, headers=headers or {})
            resp = self._conn.getresponse()
            return resp.status, resp.read()
        finally:
            self._conn.close()


WARRANT_HEADER = "X-Tenuo-Warrant"
POP_HEADER = "X-Tenuo-PoP"
# The authorizer ships as a published container image (Docker Hub), pinned in
# lockstep with the `tenuo` PyPI package. Override with TENUO_AUTHORIZER_IMAGE or
# an `authorizer.image` key in tenuo.yaml.
DEFAULT_AUTHZ_IMAGE = "tenuo/authorizer:0.3.0"

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
# The command-execution tool class: distinct shell front-ends over a `command`
# string. Each is an independent capability (see TOOL_DEFAULTS rationale above).
COMMAND_EXEC_TOOLS = frozenset({"Bash", "PowerShell", "Monitor"})
_CAP_TO_CLAUDE = {cap: tool for tool, (cap, *_) in TOOL_DEFAULTS.items()}


def claude_tool_for_cap(cap: str) -> str:
    """Map a Tenuo capability back to the Claude tool name (fallback: cap)."""
    return _CAP_TO_CLAUDE.get(cap, cap)
# Catch-all capability/tool names. "audit" is granted in the warrant (allow +
# log); "unlisted" is intentionally NOT granted, so routing to it yields a
# signed DENY receipt (used when default: deny).
CATCHALL_AUDIT = "audit"
CATCHALL_DENY = "unlisted"


def slug(name: str) -> str:
    return name.lower().replace("-", "_")


def wiring_command_parts(subcommand: str) -> tuple[str, list[str]]:
    """Resolve a PATH-independent command for Claude hooks / MCP wiring.

    Claude Code launches the wired command in a shell whose PATH may NOT contain
    our venv (e.g. a `uv run` checkout where the venv is never persistently on
    PATH). A bare `tenuo-claude` there resolves to command-not-found (exit 127),
    the hook never runs, and the tool call PROCEEDS UNGOVERNED — a silent
    fail-open. So we never emit a bare name; every branch yields an *absolute*,
    PATH-independent invocation.

    Priority:
      1. ``TENUO_CLAUDE_BIN`` (operator override, used as-is).
      2. Absolute path to the repo ``bin/tenuo-claude`` when it's executable.
      3. ``<sys.executable> -m tenuo_claude_code.cli`` — the most robust, works
         with zero PATH (absolute interpreter + importable module).
      4. Absolute ``shutil.which("tenuo-claude")`` as a last resort.
    """
    override = os.environ.get("TENUO_CLAUDE_BIN", "").strip()
    if override:
        return override, [subcommand]
    if LAUNCHER.is_file() and os.access(LAUNCHER, os.X_OK):
        return str(LAUNCHER.resolve()), [subcommand]
    if sys.executable:
        return sys.executable, ["-m", "tenuo_claude_code.cli", subcommand]
    for name in (CLI_COMMAND, CLI_COMMAND_LEGACY):
        found = shutil.which(name)
        if found:
            return str(Path(found).resolve()), [subcommand]
    # No interpreter and nothing on PATH: surface the bare command rather than
    # silently mis-wire — `check` will flag it as unresolvable.
    return CLI_COMMAND, [subcommand]


def wiring_command_string(subcommand: str) -> str:
    cmd, args = wiring_command_parts(subcommand)
    return shlex.join([cmd, *args])


# Exact deny JSON the PreToolUse hook emits; the fail-closed launcher guard
# reproduces this byte-for-byte so a launch failure BLOCKS instead of allows.
_GUARD_DENY_JSON = json.dumps({"hookSpecificOutput": {
    "hookEventName": "PreToolUse", "permissionDecision": "deny",
    "permissionDecisionReason": "Tenuo hook launcher missing (fail-closed)"}})


def hook_wiring_command_string(subcommand: str) -> str:
    """PreToolUse hook command, wrapped in a fail-closed launcher guard.

    Part 1 (``wiring_command_parts``) makes the wired command PATH-independent,
    but the resolved launcher can still vanish later (venv moved/deleted). On
    POSIX we wrap it in a ``/bin/sh -c`` guard: if the launcher is no longer
    executable at runtime, emit the deny JSON and ``exit 2`` so the tool is
    BLOCKED rather than allowed; otherwise ``exec`` the real hook so its stdout
    and exit code are preserved exactly. ``/bin/sh`` is always present on
    macOS/Linux. On Windows there is no portable ``sh`` here, so we fall back to
    the absolute command from part 1 alone (``check`` still flags an
    unresolvable launcher loudly).
    """
    cmd, args = wiring_command_parts(subcommand)
    if os.name != "posix":
        return shlex.join([cmd, *args])
    # The launcher to probe: for the `python -m` branch this is the interpreter,
    # otherwise the resolved binary itself. Both are absolute (part 1).
    launcher = cmd
    exec_line = " ".join(shlex.quote(p) for p in (cmd, *args))
    deny = shlex.quote(_GUARD_DENY_JSON)
    guard = (
        f"if [ -x {shlex.quote(launcher)} ]; then exec {exec_line}; "
        f"else printf '%s' {deny}; exit 2; fi"
    )
    return shlex.join(["/bin/sh", "-c", guard])


def mcp_wiring(cfg: dict) -> dict | None:
    """Expected ``.mcp.json`` content when ``mcp.downstream`` is configured."""
    if not cfg.get("mcp", {}).get("downstream"):
        return None
    cmd, args = wiring_command_parts("_mcp-proxy")
    return {"mcpServers": {MCP_SERVER_NAME: {"command": cmd, "args": args}}}


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


def posture_advisories(cfg: dict) -> list[str]:
    """Deprecation + degradation notices for the posture model.

    Combines the deprecated-key notices recorded at load time with a live advisory
    when an approval gate can't be honored. Human-in-the-loop approval — anywhere:
    `default: approve`, an `enforce.<tool>.approval` block, `enforce.WebFetch.approval`,
    or `mcp.enforce.<tool>.approval` — is a Tenuo Cloud feature: the gate lives in the
    Cloud-issued warrant, so without Cloud those gated tools fall back to DENY.
    Surfaced from check/refresh/status — never the hook hot path.
    """
    notes = list(cfg.get("_deprecations") or [])
    if has_approval_gates(cfg):
        creds = cloud_creds(cfg)
        if not (creds.get("url") and creds.get("api_key") and trigger_id(cfg)):
            notes.append("human-in-the-loop approval requires Tenuo Cloud — the gate "
                         "lives in the Cloud-issued warrant. Until `tenuo-admin setup`, "
                         "every approval-gated tool (and `default: approve`) DENIES.")
    return notes


def subagent_roles(cfg: dict) -> dict:
    """Declared subagent roles (name -> {tools, ttl_seconds, ...}); {} when none."""
    return cfg.get("subagents") or {}


# Default session warrant lifetime when `ttl_seconds` is absent (1 hour).
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


def validate_webfetch_policy(cfg: dict) -> None:
    """Reject `enforce.WebFetch.approval` combined with `cidrs` (fail closed).

    Approval relaxes the host constraint to a wildcard and, for internal egress,
    turns off block_private — so a `cidrs:` allowlist meant to permit ONE private
    range would silently let EVERY private range reach the human gate, and the
    gate's domain-only exempt can't represent CIDR membership. The two mechanisms
    don't compose with today's url_safe primitives, so we refuse the combination
    rather than emit a policy that's wider than it reads. Enforced once in
    load_config, so local mint, Cloud build, and verify all see the same error.
    """
    wf = (cfg.get("enforce") or {}).get("WebFetch")
    if isinstance(wf, dict) and wf.get("approval") and wf.get("cidrs"):
        raise SystemExit(
            "enforce.WebFetch: `approval` cannot be combined with `cidrs`.\n"
            "  Approval wildcards the host and permits all private ranges to reach "
            "the gate, so the cidrs allowlist would not be enforced.\n"
            "  Use `domains:` with approval, or drop `approval` to hard-enforce cidrs.")


# Fallback constrained arg per downstream MCP tool, used only when a policy
# doesn't name one (back-compat for the shipped examples). The `arg:`/`args:`
# keys in mcp.enforce are the general mechanism; this table is just a default.
MCP_ARG_FIELD = {
    "read_file": "path",
    "list_directory": "path",
    "delete_deployment": "target",
}


# Keys a structured mcp.enforce entry may contain.
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
            entries.append((tool, parsed["approval"]))
    if default_mode(cfg) == "approve":
        entries.append((CATCHALL_AUDIT, {"threshold": 1}))
    return entries


def has_approval_gates(cfg: dict) -> bool:
    return bool(approval_entries(cfg))


def approval_policy_id(cfg: dict, tenuo_tool: str | None = None) -> str | None:
    """Cloud approval policy id for a governed capability (session-wide by default)."""
    st = load_cloud_state()
    policies = st.get("approval_policies")
    if isinstance(policies, dict):
        if tenuo_tool and policies.get(tenuo_tool):
            return policies[tenuo_tool]
        if policies.get("*"):
            return policies["*"]
    return st.get("session_approval_policy_id") or st.get("web_fetch_approval_policy_id")


# Policy posture (`mode:` in tenuo.yaml). `dry-run` is the canonical observe-only
# value; `audit` is the deprecated spelling kept working for back-compat.
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


def _managed_enforce_pinned() -> bool:
    """True when the MDM-pinned managed hook is running (``TENUO_MANAGED_ENFORCE``).

    The generated ``managed-settings.json`` wires the ``_managed-hook`` entrypoint,
    which sets this env var. That command lives in Claude Code's highest-precedence,
    developer-unwritable settings tier, so it is an AUTHORITATIVE managed signal
    that editable project files (``tenuo.yaml`` / ``.state/cloud_state.json``)
    cannot forge away. A developer could only ever SET it (forcing enforce), never
    unset it for the pinned hook, so honoring it can only tighten enforcement.
    """
    return os.environ.get("TENUO_MANAGED_ENFORCE", "") not in ("", "0", "false", "False")


def managed_mode(cfg: dict) -> bool:
    """Org-managed Cloud mode: the Cloud trigger is the sole authority and the
    local policy is overlay/attenuation only.

    Authority signals, strongest first:
      1. the MDM-pinned managed hook (``TENUO_MANAGED_ENFORCE``) — unforgeable by
         local edits, so the per-call enforcement path can't be downgraded;
      2. the resolved `cfg["_managed"]` (set by `load_config`);
      3. `cloud.managed` in policy or `managed` in `.state/cloud_state.json`
         (written by `tenuo-admin setup --managed`).

    The flag/state in (2)/(3) is convenience for the cooperative CLI (messaging,
    fail-closed `up`); the real boundary is (1) plus the authorizer trusting ONLY
    the Cloud root, so a locally-minted warrant won't verify regardless of this.
    """
    if _managed_enforce_pinned():
        return True
    if "_managed" in cfg:
        return bool(cfg["_managed"])
    return bool((cfg.get("cloud") or {}).get("managed") or load_cloud_state().get("managed"))


def is_audit_mode(cfg: dict) -> bool:
    """Global observe-only posture (`mode: dry-run` in tenuo.yaml).

    When on, the hook and MCP proxy still compute the REAL allow/deny against the
    warrant and write it to the signed receipt — but never block. You get the
    full audit trail (including what WOULD be denied) with zero enforcement, for
    safe rollout / shadowing. Flip back with `mode: enforce` (the default).

    Managed Cloud mode pins the posture to enforce: an org that manages the fleet
    does not let an individual endpoint quietly switch itself to observe-only.
    """
    return policy_mode(cfg) == MODE_DRY_RUN and not managed_mode(cfg)


def is_dry_run_mode(cfg: dict) -> bool:
    """Alias for the current posture vocabulary; kept for newer call sites."""
    return is_audit_mode(cfg)


def posture_warnings(cfg: dict) -> list[str]:
    """Human-readable warnings about the policy's posture vocabulary.

    Compatibility wrapper for older call sites/tests. The newer loader validates
    posture vocabulary and records deprecations in ``_deprecations``; managed mode
    still adds the important advisory that local dry-run is pinned to enforce.
    """
    out: list[str] = []
    raw_mode = str(cfg.get("mode", MODE_ENFORCE)).strip().lower()
    if managed_mode(cfg) and policy_mode(cfg) == MODE_DRY_RUN:
        out.append("mode: dry-run is pinned to enforce by org-managed Cloud mode "
                   "(the local observe-only posture is ignored on managed endpoints).")
    elif raw_mode == "audit":
        out.append("mode: audit is deprecated, use mode: dry-run (same observe-only behavior).")
    out.extend(posture_advisories(cfg))
    return out


def policy_capability_fingerprint(cfg: dict) -> str:
    """Stable hash of the policy inputs that a Cloud trigger bakes into warrants.

    Covers exactly what `tenuo-admin setup` encodes into the trigger's
    warrant_config: enforced capabilities + their constraint specs, audit-allow
    capabilities, MCP-enforced tools, subagent roles, approval gates, and the
    catch-all default. Used to
    detect when tenuo.yaml has drifted from the issued warrant — in Cloud mode,
    capability changes only take effect after re-running `tenuo-admin setup`, so a
    plain `refresh` silently ignores them.

    Deliberately EXCLUDES local-only knobs that don't change the warrant: `mode`
    (enforce/audit is a runtime posture) and the sandbox path (passed as fire-time
    event_data, not baked into the trigger). The raw constraint spec strings carry
    the `{sandbox}` placeholder verbatim, so they're stable across machines.
    """
    import hashlib

    enforce = {}
    for tool, spec in (cfg.get("enforce", {}) or {}).items():
        if isinstance(spec, dict):  # WebFetch structured policy
            enforce[tool] = {k: spec.get(k) for k in
                             ("domains", "cidrs", "schemes", "ports", "approval")}
        else:
            enforce[tool] = str(spec)
    mcp_enforce = {t: (s if isinstance(s, (str, dict)) else str(s))
                   for t, s in ((cfg.get("mcp", {}) or {}).get("enforce") or {}).items()}
    subagents = {r: sorted((v or {}).get("tools", []) or [])
                 for r, v in (cfg.get("subagents", {}) or {}).items()}
    payload = {
        "enforce": enforce,
        "mcp_enforce": mcp_enforce,
        "subagents": subagents,
        "approval": sorted(t for t, _ in approval_entries(cfg)),
        "audit": sorted(set(audit_map(cfg).values())),
        "default": default_mode(cfg),
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def load_harness_tools() -> list[str]:
    import yaml

    if not HARNESS_TOOLS_FILE.exists():
        return []
    data = yaml.safe_load(HARNESS_TOOLS_FILE.read_text()) or {}
    return [str(t) for t in (data.get("tools") or [])]


def _deep_merge(base: dict, overlay: dict) -> None:
    for k, v in overlay.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


def load_config() -> dict:
    import yaml

    if not CONFIG_FILE.exists():
        raise SystemExit(f"Missing {CONFIG_FILE}")
    cfg = yaml.safe_load(CONFIG_FILE.read_text()) or {}
    if CLOUD_PROFILE.exists():
        overlay = yaml.safe_load(CLOUD_PROFILE.read_text()) or {}
        _deep_merge(cfg, overlay)
    if ADVANCED_PROFILE.exists():
        overlay = yaml.safe_load(ADVANCED_PROFILE.read_text()) or {}
        _deep_merge(cfg, overlay)
    cfg.setdefault("sandbox", "./sandbox")
    cfg["_sandbox_abs"] = str((DEMO_DIR / cfg["sandbox"]).resolve())
    cfg.setdefault("enforce", {})
    cfg.setdefault("mcp", {})
    # Resolve managed Cloud mode once (policy flag or cloud-setup state) so the
    # per-call hook path doesn't re-read cloud_state.json on every tool call.
    try:
        state_managed = load_cloud_state().get("managed")
    except Exception:
        state_managed = None
    cfg["_managed"] = bool((cfg.get("cloud") or {}).get("managed") or state_managed)
    # Permit-list ("allow") + bundled toggle ("allow_bundled"), with the legacy
    # audit* keys accepted as deprecated aliases. Everything normalizes into the
    # internal `cfg["audit"]` representation so the rest of the code is unchanged.
    deps = _normalize_posture_keys(cfg)
    user_allow = list(cfg.get("allow") or [])
    if isinstance(cfg.get("audit"), list):
        deps.append("`audit:` is deprecated — rename to `allow:`")
        user_allow += cfg["audit"]
    if cfg.get("audit_extra"):
        deps.append("`audit_extra:` is deprecated — fold its tools into `allow:`")
        user_allow += [str(t) for t in cfg["audit_extra"]]
    bundled_on = cfg.get("allow_bundled")
    if bundled_on is None and "audit_bundled" in cfg:
        deps.append("`audit_bundled:` is deprecated — rename to `allow_bundled:`")
        bundled_on = cfg.get("audit_bundled")
    if bundled_on is None:
        bundled_on = True
    if bundled_on:
        # Command-execution tools are never harness-inert: auto-allowing would grant
        # an unconstrained shell. Defensive guard so a future edit to the shipped
        # bundle can't silently allow one — they must be governed via `enforce`.
        merged_src = [t for t in load_harness_tools() if t not in COMMAND_EXEC_TOOLS] + user_allow
    else:
        merged_src = list(user_allow)
    seen: set[str] = set()
    audit: list[str] = []
    for t in merged_src:
        if t not in seen:
            seen.add(t)
            audit.append(t)
    cfg["audit"] = audit          # internal canonical (read by audit_map, status, …)
    cfg["_deprecations"] = deps
    validate_webfetch_policy(cfg)
    if cfg.get("ttl_seconds") is not None:
        validate_ttl_seconds(cfg["ttl_seconds"])
    return cfg


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


def _range_bound(text: str, spec: str):
    """Parse one side of a `range:min,max` bound; blank means open-ended (None)."""
    text = text.strip()
    if not text:
        return None
    try:
        return float(text) if ("." in text or "e" in text.lower()) else int(text)
    except ValueError:
        raise SystemExit(f"range bound '{text}' is not a number in '{spec}'.")


def parse_range_spec(spec: str) -> tuple:
    """Validate a `range:min,max` spec and return (lo, hi) bounds (None = open).

    Shared by local mint (make_constraint) and Cloud wire (admin.to_wire_constraint)
    so both reject the same specs. A blank side is open-ended, but not both (that
    is a match-all range), and a missing comma (`range:5`) is rejected outright —
    otherwise Cloud would silently emit `..` (match-all) or `5..` for inputs the
    local authorizer refuses.
    """
    _, _, rest = spec.partition(":")
    if "," not in rest:
        raise SystemExit(
            f"range constraint needs 'min,max' (either side may be blank) in '{spec}'.")
    lo, _, hi = rest.partition(",")
    lo_v, hi_v = _range_bound(lo, spec), _range_bound(hi, spec)
    if lo_v is None and hi_v is None:
        raise SystemExit(f"range constraint needs at least one bound in '{spec}'.")
    return lo_v, hi_v


def make_constraint(spec: str, sandbox: str):
    """Constraint DSL -> tenuo constraint object."""
    from tenuo import (Cidr, Exact, NotOneOf, OneOf, Pattern, Range, Regex,
                       Subpath, UrlPattern)
    from tenuo_core import Shlex  # core constraint type (mintable)

    spec = spec.replace("{sandbox}", sandbox)
    kind, _, rest = spec.partition(":")
    if kind == "subpath":
        return Subpath(rest)
    if kind == "shlex":
        return Shlex(allow=[v.strip() for v in rest.split(",") if v.strip()])
    if kind == "regex":
        return Regex(rest)
    if kind == "pattern":
        return Pattern(rest)
    if kind == "oneof":
        return OneOf([v.strip() for v in rest.split(",")])
    if kind == "notoneof":
        return NotOneOf([v.strip() for v in rest.split(",")])
    if kind == "exact":
        return Exact(rest)
    if kind == "urlpattern":
        return UrlPattern(rest)
    if kind == "cidr":
        # Any tool argument that is an IP/host (not just WebFetch): the value
        # must fall inside the CIDR block. Non-IP values fail closed.
        return Cidr(rest)
    if kind == "range":
        return Range(*parse_range_spec(spec))
    raise SystemExit(
        f"Unknown constraint kind '{kind}' in '{spec}'. "
        "Valid kinds: subpath, shlex, regex, pattern, oneof, notoneof, exact, "
        "range, urlpattern, cidr (or a WebFetch policy with domains/cidrs). "
        "Syntax: <kind>:<value>, e.g. subpath:{sandbox} or cidr:10.0.0.0/8.")


def parse_ports(policy: dict) -> list[int] | None:
    """Validate a WebFetch `ports:` allowlist -> list[int], or None when unset.

    Shared by local mint (make_web_constraints) and Cloud wire
    (admin.url_safe_ssrf_wire) so a malformed entry fails with one clear policy
    error on both paths instead of a Python traceback. Ports are u16 in core.
    """
    raw = policy.get("ports")
    if not raw:
        return None
    out: list[int] = []
    for p in raw:
        try:
            n = int(p)
        except (TypeError, ValueError):
            raise SystemExit(f"tenuo.yaml WebFetch `ports:` must be integers, got {p!r}")
        if not 1 <= n <= 65535:
            raise SystemExit(f"tenuo.yaml WebFetch `ports:` value {n} out of range (1-65535)")
        out.append(n)
    return out


def make_web_constraints(policy: dict, *, approval_gate: bool = False) -> dict:
    """Org egress policy -> {url: UrlSafe, host: AnyOf(domains|cidrs) or Wildcard}.

    approval_gate=True: SSRF-only url + wildcard host; domain policy moves to Cloud gate.
    """
    from tenuo_core import AnyOf, Cidr, Pattern, UrlSafe, Wildcard

    domains = [str(d) for d in policy.get("domains") or []]
    cidrs = [str(c) for c in policy.get("cidrs") or []]
    if not domains and not cidrs:
        raise SystemExit("WebFetch policy needs at least one of: domains, cidrs")
    # https-only unless internal ranges are in play (internal services are
    # often plain http); explicit `schemes:` in the policy overrides.
    schemes = [str(s) for s in policy.get("schemes") or
               (["https"] if not cidrs else ["http", "https"])]
    kwargs = dict(allow_schemes=schemes,
                  block_private=not cidrs, block_loopback=True,
                  block_metadata=True, block_reserved=True)
    ports = parse_ports(policy)
    if ports:
        kwargs["allow_ports"] = ports
    url = UrlSafe(**kwargs)
    if approval_gate:
        return {"url": url, "host": Wildcard()}
    members = [Pattern(d) for d in domains] + [Cidr(c) for c in cidrs]
    host = members[0] if len(members) == 1 else AnyOf(members)
    return {"url": url, "host": host}


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


def subwarrant_path(role: str) -> Path:
    return STATE / f"subwarrant_{slug(role)}.b64"


def refresh_subwarrants(cfg: dict) -> None:
    """Mint one attenuated child warrant per declared subagent role.

    Each child is the live session (parent) warrant narrowed to the role's tool
    subset, delegated to the same holder. The parent is the ceiling: a subagent
    can only ever do LESS than the session, never more — and the parent->child
    delegation is what the audit trail shows. Re-minted on every `up` so the
    children always chain to the current session warrant. Works identically for
    locally-minted and Cloud-issued session warrants.
    """
    for stale in STATE.glob("subwarrant_*.b64"):
        stale.unlink()
    roles = subagent_roles(cfg)
    if not roles:
        return
    from tenuo import SigningKey, Warrant
    from tenuo.exceptions import UntrustedRoot
    from tenuo_core import encode_warrant_stack

    try:
        parent = Warrant.from_base64(WARRANT.read_text())
    except UntrustedRoot as e:
        raise SystemExit(
            f"Warrant trust verification failed: {e}\n"
            "The session warrant is not signed by a trusted issuer.\n"
            "This may indicate a Cloud trust policy change.\n"
            "Fix: tenuo-claude check  (verify warrant validity)"
        ) from e
    holder = SigningKey.from_bytes(base64.b64decode(HOLDER_KEY.read_text()))
    parent_caps = set((parent.capabilities or {}).keys())
    for role, rc in roles.items():
        rc = rc or {}
        caps = []
        for tool in rc.get("tools") or []:
            if tool not in TOOL_DEFAULTS:
                raise SystemExit(f"subagents.{role}: unknown tool '{tool}'")
            caps.append(TOOL_DEFAULTS[tool][0])
        missing = [c for c in caps if c not in parent_caps]
        if missing:
            raise SystemExit(
                f"subagents.{role}: {missing} not granted by the session warrant. "
                "A subagent can't exceed the parent — add the tool to `enforce` first.")
        builder = parent.attenuate_builder()
        builder.inherit_all()
        builder.with_tools(caps)  # retain subset, keep the parent's constraints
        builder.with_intent(f"subagent:{role}")
        if rc.get("ttl_seconds"):
            builder.with_ttl(int(rc["ttl_seconds"]))
        try:
            child = builder.delegate(holder)
        except Exception as e:
            from tenuo.exceptions import DelegationAuthorityError
            if isinstance(e, DelegationAuthorityError) and "signing key mismatch" in str(e):
                raise SystemExit(
                    "Holder signing key does not match the session warrant.\n"
                    "Local .state/holder_key.b64 drifted from the Cloud-claimed agent key.\n"
                    "Fix: tenuo-admin setup  (will re-claim the holder key)"
                ) from e
            raise
        # Persist the full chain (parent..child): a delegated warrant must be
        # presented as a WarrantStack so the authorizer can verify to the root.
        write_secret(subwarrant_path(role),
                     encode_warrant_stack([parent, child]))


def _parse_env_value(raw: str) -> str:
    """Parse one KEY=VALUE tail from a shell-style env file."""
    raw = raw.strip()
    if not raw:
        return ""
    if raw[0] in '"\'':
        q = raw[0]
        end = raw.find(q, 1)
        if end != -1:
            return raw[1:end]
        return raw.strip(q)
    # Unquoted: strip trailing inline comment.
    if "#" in raw:
        raw = raw[: raw.index("#")].strip()
    return raw.strip().strip('"').strip("'")


def read_env_file(path: Path) -> dict:
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = _parse_env_value(v)
    return env


def runtime_env() -> dict:
    """Process environment overlaid with .state/cloud.env (the runtime/authorizer
    credentials). The single place those two sources are merged."""
    env = dict(os.environ)
    env.update(read_env_file(CLOUD_ENV))
    return env


def _parse_connect_token(raw: str) -> dict:
    """Extract endpoint + API key from a dashboard Quick Connect token."""
    try:
        from tenuo_core import ConnectToken

        ct = ConnectToken.parse(raw)
        return {"url": ct.endpoint, "api_key": ct.api_key}
    except ImportError as e:
        raise SystemExit(
            "TENUO_CONNECT_TOKEN requires the tenuo_core extension "
            "(bundled with tenuo>=0.3.0)."
        ) from e
    except Exception as e:
        raise SystemExit(f"Invalid TENUO_CONNECT_TOKEN: {e}") from e


# ---------------------------------------------------------------------------
# Enforcement core (shared by the hook, the MCP proxy, verify, and tenuo_demo)
# ---------------------------------------------------------------------------


def _authorization_receipt_context(tenuo_tool: str, route: str, sign_args: dict,
                                   warrant_b64: str, pop_b64: str | None,
                                   pop_ts: int | None,
                                   approvals_b64: str | None = None) -> dict:
    """Evidence needed to replay a governed decision from the receipt alone.

    The receipt stores the exact warrant header presented to the authorizer, plus
    a hash for quick tamper diagnostics. Verification still decodes and validates
    the warrant chain against a separately configured trust root; it never trusts
    the issuer just because it appeared in the receipt.
    """
    stack_bytes = _decode_b64url_or_standard(warrant_b64)
    chain = _decode_warrant_header(warrant_b64)
    leaf = chain[-1]
    ctx = {
        "authz_evidence_version": 1,
        "warrant_stack_b64": warrant_b64,
        "warrant_stack_hash": hashlib.sha256(stack_bytes).hexdigest(),
        "warrant_chain_ids": [w.id for w in chain],
        "warrant_id": leaf.id,
        "tenuo_tool": tenuo_tool,
        "route": route,
        "sign_args": sign_args,
        "pop_b64": pop_b64,
        "pop_ts": pop_ts,
    }
    if approvals_b64:
        ctx["approvals_b64"] = approvals_b64
        ctx["approval_required"] = True
    return ctx


def _authorize_attempt(tenuo_tool: str, route: str, sign_args: dict, body,
                       warrant_b64: str | None, approvals_b64: str | None = None):
    """One signed authorizer call. Returns (allowed, reason, response_body|{}, evidence).

    Fail-closed: any signing/transport error -> (False, reason, {}). `approvals_b64`
    attaches base64-CBOR SignedApproval(s) (the X-Tenuo-Approvals header) so a
    previously approval-gated call can be re-authorized.
    """
    evidence = {}
    try:
        from tenuo import SigningKey
        from tenuo_core import decode_warrant_stack_base64

        holder = SigningKey.from_bytes(base64.b64decode(HOLDER_KEY.read_text()))
        header_b64 = warrant_b64 if warrant_b64 is not None else WARRANT.read_text()
        # The header may carry a single warrant or a WarrantStack; either decodes
        # to a chain (single -> length 1). The leaf (last) is what signs the PoP.
        try:
            leaf = decode_warrant_stack_base64(header_b64)[-1]
        except Exception as e:
            from tenuo import Warrant
            from tenuo.exceptions import UntrustedRoot
            try:
                leaf = Warrant.from_base64(header_b64)
            except UntrustedRoot as ute:
                return False, f"warrant trust failed: {ute}", {}, evidence
        pop_ts = int(time.time())
        pop = leaf.sign(holder, tenuo_tool, sign_args, pop_ts)
        pop_b64 = base64.b64encode(bytes(pop)).decode("ascii")
        evidence = _authorization_receipt_context(
            tenuo_tool, route, sign_args, header_b64, pop_b64, pop_ts, approvals_b64)
        headers = {
            WARRANT_HEADER: header_b64,
            POP_HEADER: pop_b64,
            "Content-Type": "application/json",
        }
        if approvals_b64:
            headers[APPROVALS_HEADER] = approvals_b64
        data = json.dumps(body).encode()
    except Exception as exc:
        return False, f"enforcement error ({exc})", {}, evidence

    mode, loc = authz_endpoint()
    if mode == "unix":
        allowed, reason, rb = _authorize_over_uds(loc, route, headers, data)
        return allowed, reason, rb, evidence
    try:
        req = urllib.request.Request(loc + route, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            rb = json.loads(resp.read().decode() or "{}")
            if resp.status == 200 and rb.get("authorized"):
                return True, "authorized", rb, evidence
            return False, rb.get("message") or rb.get("error") or f"status {resp.status}", rb, evidence
    except urllib.error.HTTPError as exc:
        try:
            rb = json.loads(exc.read().decode() or "{}")
            return False, rb.get("message") or rb.get("error") or f"status {exc.code}", rb, evidence
        except Exception:
            return False, f"status {exc.code}", {}, evidence
    except Exception as exc:
        return False, f"authorizer unreachable, denying ({exc})", {}, evidence


def _authorize_over_uds(socket_path: str, route: str, headers: dict, data: bytes):
    """Send a signed authorize call over a Unix socket. Fail-closed: an unsafe,
    missing, or unreachable socket denies. Mirrors the TCP branch's response shape.
    """
    if os.name != "posix":
        return False, "unix authorizer transport requires POSIX", {}
    ok, why = _safe_managed_socket(socket_path, managed=_managed_enforce_pinned())
    if not ok:
        return False, f"refusing untrusted authorizer socket: {why}", {}
    try:
        status, raw = _UDSConnection(socket_path, timeout=5).request("POST", route, headers, data)
        rb = json.loads(raw.decode() or "{}")
        if status == 200 and rb.get("authorized"):
            return True, "authorized", rb
        return False, rb.get("message") or rb.get("error") or f"status {status}", rb
    except Exception as exc:
        return False, f"authorizer unreachable, denying ({exc})", {}


def authorize(tenuo_tool: str, route: str, sign_args: dict, body=None,
              warrant_b64: str | None = None):
    """Sign PoP, ask the authorizer. Returns (allowed, reason). Fail-closed.

    `warrant_b64` overrides the session warrant — used to present a subagent's
    attenuated child warrant. A subagent's credential is a full WarrantStack
    (child + parent chain), needed so the authorizer can verify back to the
    trusted root; the LEAF signs the PoP. The holder key is the same in both
    cases (children are delegated to the session holder), so signing is uniform.
    """
    allowed, reason, _, _ = _authorize_attempt(
        tenuo_tool, route, sign_args, sign_args if body is None else body, warrant_b64)
    return allowed, reason


# `error_code` the authorizer returns when a gated capability is invoked without
# the required approvals (the call is paused, not denied — provide signatures).
APPROVAL_REQUIRED_CODE = 1707
APPROVALS_HEADER = "X-Tenuo-Approvals"
# Bounded wait for the approver. Kept under the Claude hook timeout budget.
# `timeout` set in generate() so the hook resolves rather than being killed.
APPROVAL_POLL_SECONDS = 150
APPROVAL_POLL_INTERVAL = 3
APPROVAL_TTL_SECONDS = 300
# Prefix the runtime uses to mark a "would require human approval" outcome so the
# hook (audit mode) and verify can distinguish it from a hard deny.
APPROVAL_PENDING_REASON = "approval required"


def encode_approvals_header(sigs: list) -> str:
    """Encode SignedApproval blob(s) for X-Tenuo-Approvals.

    The authorizer accepts base64 of either a single SignedApproval CBOR or a
    CBOR array of them. Each Cloud `signed_approval` is base64 of one CBOR blob,
    so a threshold-1 response passes through as-is; for N > 1 we wrap the decoded
    blobs in a CBOR array (header byte 0x80|N + concatenated items — valid for
    N < 24, far above any sane approval threshold).
    """
    if len(sigs) == 1:
        return sigs[0]
    items = [base64.b64decode(s) for s in sigs[:23]]
    return base64.b64encode(bytes([0x80 | len(items)]) + b"".join(items)).decode()


def request_cloud_approval(creds: dict, policy_id: str, claude_tool: str, tenuo_tool: str,
                           args: dict, rb: dict, warrant_b64: str | None):
    """Create a Cloud approval request, poll until resolved, return signed approval(s).

    Returns (signatures, reason). Signatures are base64 CBOR blobs for
    X-Tenuo-Approvals. The request_hash and attestation bind to the exact args.
    """
    from tenuo import SigningKey
    from tenuo.cp_approval import build_approval_context_attestation
    from tenuo_core import decode_warrant_stack_base64

    request_hash = rb.get("request_hash")
    if not request_hash:
        return [], "authorizer gave no request_hash for approval"
    try:
        holder = SigningKey.from_bytes(base64.b64decode(HOLDER_KEY.read_text()))
        header_b64 = warrant_b64 if warrant_b64 is not None else WARRANT.read_text()
        warrant_id = decode_warrant_stack_base64(header_b64)[-1].id
        # The attestation recomputes the request_hash from the SAME (warrant, tool,
        # args, holder) the authorizer hashed; if they diverge the gate args differ
        # and the approval would not apply — surface it rather than prompt a human.
        _, meta = build_approval_context_attestation(
            holder, warrant_id, tenuo_tool, args, holder.public_key)
    except Exception as exc:
        return [], f"could not build approval attestation ({exc})"
    if meta.get("request_hash") != request_hash:
        return [], (f"approval hash mismatch — gate args differ "
                    f"(authz={request_hash[:12]}…, local={str(meta.get('request_hash'))[:12]}…)")

    body = {
        "policy_id": policy_id,
        "warrant_id": warrant_id,
        "tool": tenuo_tool,
        "request_hash": request_hash,
        "holder_key": holder.public_key.to_bytes().hex(),
        "args_canonical_cbor_b64": meta["args_canonical_cbor_b64"],
        "approval_context_attestation": meta,
        "metadata": {"source": "claude-code", **args},
        "threshold": int(rb.get("required_approvals") or 1),
        "approver_keys": rb.get("required_approvers") or [],
        "ttl_seconds": APPROVAL_TTL_SECONDS,
    }
    status, resp = cloud_api("POST", creds["url"], creds["api_key"],
                             "/v1/approvals/requests", body)
    if status not in (200, 201) or not isinstance(resp, dict) or not resp.get("id"):
        return [], f"approval request rejected ({status}): {resp}"
    rid = resp["id"]
    receipt_base = {"phase": "pre", "source": "approval", "claude_tool": claude_tool,
                    "tenuo_tool": tenuo_tool, "args": args, "approval_request_id": rid}
    write_receipt({**receipt_base, "decision": "pending",
                   "reason": "awaiting human approval"})

    deadline = time.time() + APPROVAL_POLL_SECONDS
    while time.time() < deadline:
        time.sleep(APPROVAL_POLL_INTERVAL)
        s, ar = cloud_api("GET", creds["url"], creds["api_key"],
                          f"/v1/approvals/requests/{rid}")
        if s != 200 or not isinstance(ar, dict):
            continue
        st = ar.get("status")
        if st == "approved":
            # Go marshals []byte as standard base64; the authorizer accepts it
            # directly for X-Tenuo-Approvals (single SignedApproval CBOR).
            sigs = [r.get("signed_approval") for r in (ar.get("responses") or [])
                    if r.get("signed_approval")]
            if sigs:
                write_receipt({**receipt_base, "decision": "allow",
                               "reason": "approved"})
                return sigs, "approved"
            write_receipt({**receipt_base, "decision": "deny",
                           "reason": "approved but no signature returned"})
            return [], "approved but no signature returned"
        if st == "denied":
            reason = f"denied by approver ({ar.get('denied_reason') or 'no reason given'})"
            write_receipt({**receipt_base, "decision": "deny", "reason": reason})
            return [], reason
        if st == "expired":
            write_receipt({**receipt_base, "decision": "deny",
                           "reason": "approval window expired"})
            return [], "approval window expired"
    write_receipt({**receipt_base, "decision": "deny",
                   "reason": "approval timed out (no response from approver)"})
    return [], "approval timed out (no response from approver)"


def authorize_with_approval(cfg: dict, claude_tool: str, tenuo_tool: str, route: str,
                            sign_args: dict, body, warrant_b64: str | None, live: bool):
    """authorize() + Cloud approval retry on 1707. live=False = report-only (verify/demo)."""
    if body is None:
        body = sign_args
    allowed, reason, rb, evidence = _authorize_attempt(
        tenuo_tool, route, sign_args, body, warrant_b64)
    if allowed:
        return True, reason, evidence
    if not (isinstance(rb, dict) and rb.get("error_code") == APPROVAL_REQUIRED_CODE):
        return False, reason, evidence

    creds = cloud_creds(cfg)
    policy_id = approval_policy_id(cfg, tenuo_tool)
    if not (creds.get("url") and creds.get("api_key") and policy_id):
        return False, ("approval required, but the Cloud approver isn't configured — "
                       "run `tenuo-admin setup` (approval gates require Tenuo Cloud)"), evidence
    threshold = int(rb.get("required_approvals") or 1)
    evidence["approval_required"] = True
    evidence["approval_threshold"] = threshold
    approvers = rb.get("required_approvers")
    if approvers:
        evidence["required_approvers"] = approvers
    if not live:
        return False, f"{APPROVAL_PENDING_REASON}: {threshold} approval(s) required", evidence

    sigs, areason = request_cloud_approval(
        creds, policy_id, claude_tool, tenuo_tool, sign_args, rb, warrant_b64)
    if not sigs:
        return False, f"{APPROVAL_PENDING_REASON} — {areason}", evidence
    approvals_header = encode_approvals_header(sigs)
    allowed, reason, _, approved_evidence = _authorize_attempt(
        tenuo_tool, route, sign_args, body, warrant_b64,
        approvals_b64=approvals_header)
    approved_evidence["approval_required"] = True
    approved_evidence["approval_threshold"] = threshold
    if approvers:
        approved_evidence["required_approvers"] = approvers
    if allowed:
        return True, "approved", approved_evidence
    return False, f"re-authorize after approval failed: {reason}", approved_evidence


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
        return g["cap"], f"/verify/{g['cap']}", args, args, True

    audit = audit_map(cfg)
    if tool_name in audit:
        cap = audit[tool_name]
        return cap, f"/verify/{cap}", {}, dict(tool_input or {}), False

    mcp_enforce = mcp_enforce_entries(cfg)
    bare = mcp_tool_name(tool_name)
    if bare is None and tool_name in mcp_enforce:
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
        return bare, f"/verify/{bare}", args, args, True

    # Catch-all. Under `default: approve` the catch-all carries a whole-tool gate
    # (every unlisted call requires approval), so we don't need to sign `tool` to
    # make the gate fire. We sign it anyway so the approval's request_hash binds per
    # tool name — approving one unlisted tool must not auto-approve another — and the
    # signed args must match what the /gate route extracts. Under `deny` the cap is
    # ungranted, so no args are checked (route extracts none) — keep sign_args empty.
    if default_mode(cfg) == "approve":
        return catchall_cap(cfg), "/gate", {"tool": tool_name}, {"tool": tool_name, **(tool_input or {})}, False
    return catchall_cap(cfg), "/gate", {}, {"tool": tool_name, **(tool_input or {})}, False


# Claude Code's subagent-spawn tool(s). Empirically "Agent" on claude 2.1.x;
# "Task" is accepted too for forward/back-compat. If Anthropic renames the spawn
# tool, spawns default-deny (safe) unless the new name lands in the audit list
# (allow+log). verify --deep checks hook exit-code contract, not spawn-tool names.
SPAWN_TOOLS = ("Agent", "Task")
# Synthetic capability: spawning a subagent. Constrained to a oneof of declared
# roles, minted locally AND issuable via a Cloud trigger, so the spawn decision
# is a signed authorizer check (not a local-only policy gate) in both modes.
SPAWN_CAP = "spawn_agent"
# Claude Code's built-in subagent types (no .md file). Declaring one of these as
# a role is valid even without an agent definition. The list can drift across
# Claude versions, so it's only used to avoid false "unresolved" warnings.
BUILTIN_SUBAGENTS = frozenset({"general-purpose", "Explore", "Plan"})


def agent_definitions() -> dict[str, Path]:
    """Map every discoverable custom subagent_type -> its definition file.

    The type is the frontmatter `name:` (Claude's actual `subagent_type`), not the
    filename. Project-level definitions win over user-level on name collision.
    """
    import yaml

    found: dict[str, Path] = {}
    for base in AGENTS_DIRS:
        if not base.is_dir():
            continue
        for md in sorted(base.glob("*.md")):
            name = md.stem
            text = md.read_text(errors="replace")
            if text.startswith("---") and (end := text.find("\n---", 3)) != -1:
                fm = yaml.safe_load(text[3:end]) or {}
                if isinstance(fm, dict) and fm.get("name"):
                    name = str(fm["name"]).strip()
            found.setdefault(name, md)
    return found


def resolve_subagent_role(role: str, defs: dict[str, Path] | None = None) -> tuple[bool, str]:
    """Does a declared role map to a real, spawnable subagent_type? -> (ok, where)."""
    defs = agent_definitions() if defs is None else defs
    if role in defs:
        try:
            return True, str(defs[role].relative_to(DEMO_DIR))
        except ValueError:
            return True, str(defs[role])
    if role in BUILTIN_SUBAGENTS:
        return True, "built-in"
    return False, "no agent definition"


def authorize_call(cfg: dict, tool: str, tin: dict, agent_type, roles: dict,
                   live: bool = False, skip_approval_gate: bool = False,
                   return_context: bool = False):
    """Decide one tool call. Returns (allowed, reason, governed, tenuo_tool).

    With ``return_context=True`` appends the authorization evidence that should be
    embedded in a receipt. The default shape stays stable for tests and callers
    that only need the decision.

    Three layers, in order:
      1. SPAWN GATE — a main-thread Agent/Task call. With `subagents:` declared,
         spawning is a SIGNED capability (`spawn_agent`, root-signed in Cloud
         mode): the warrant's oneof decides which roles pass. With NO block
         declared, it's FLAT COVERAGE — spawning isn't gated and the subagent
         just runs under the session warrant (its inner calls stay enforced), so
         the spawn is audited, not default-denied.
      2. PER-SUBAGENT WARRANT — when roles are declared, a call made INSIDE a
         subagent runs under that role's attenuated child warrant, never the
         session warrant. An undeclared role (or missing child) gets nothing —
         fail-closed.
      3. SESSION — everything else (incl. in-subagent calls under flat coverage):
         the main-thread session warrant, as before.
    """
    def done(allowed, reason, governed, tenuo_tool, evidence=None):
        out = (allowed, reason, governed, tenuo_tool)
        return (*out, evidence or {}) if return_context else out

    if tool in SPAWN_TOOLS and not agent_type:
        if not roles:
            # Flat coverage: no subagent roles -> spawning is plain orchestration.
            # The subagent's tool calls still run under the session warrant, so
            # nothing escalates; record the spawn as audited rather than denying.
            return done(True, "flat coverage (no subagent roles declared)", False, tool)
        # Signed spawn gate: ask the authorizer (root-signed in Cloud mode). The
        # warrant's spawn_agent oneof decides which declared roles may spawn.
        requested = (tin or {}).get("subagent_type") or ""
        route = f"/verify/{SPAWN_CAP}"
        sign_args = {"subagent_type": requested}
        if return_context:
            allowed, reason, _, evidence = _authorize_attempt(
                SPAWN_CAP, route, sign_args, sign_args, warrant_b64=None)
            return done(allowed, reason, True, SPAWN_CAP, evidence)
        allowed, reason = authorize(SPAWN_CAP, route, sign_args, sign_args)
        return done(allowed, reason, True, SPAWN_CAP)

    tenuo_tool, route, sign_args, body, governed = resolve_tool(cfg, tool, tin)
    warrant_b64 = None
    if agent_type and roles:
        sw = subwarrant_path(agent_type)
        if agent_type not in roles or not sw.exists():
            return done(False, f"undeclared subagent '{agent_type}'", governed, tenuo_tool)
        warrant_b64 = sw.read_text()
    # Any governed tool call can return approval-required (1707) when the warrant
    # includes an approval gate for that capability. The hook resolves it via
    # Cloud (live) or reports PAUSE (verify / demo / audit mode).
    evidence = {}
    if not skip_approval_gate:
        allowed, reason, evidence = authorize_with_approval(
            cfg, tool, tenuo_tool, route, sign_args, body, warrant_b64, live=live)
    else:
        if return_context:
            allowed, reason, _, evidence = _authorize_attempt(
                tenuo_tool, route, sign_args, sign_args if body is None else body, warrant_b64)
        else:
            allowed, reason = authorize(tenuo_tool, route, sign_args, body, warrant_b64=warrant_b64)
    # `default: approve` fails closed in the warrant, not here: the catch-all carries
    # a whole-tool approval gate, so tenuo-core requires a signed human approval for
    # every unlisted call (and the cap is granted only alongside that gate; locally
    # it's never granted, so approve falls back to deny). The authorizer is the
    # boundary — we don't re-derive its decision client-side.
    if not allowed and governed:
        reason = _augment_denial_reason(cfg, tool, reason)
    return done(allowed, reason, governed, tenuo_tool, evidence)


def _augment_denial_reason(cfg: dict, tool: str, reason: str) -> str:
    """Append a clarifying hint to a denial when the policy shape is a common trap.

    Bash uses a `shlex:` allowlist, which authorizes the command *verb*, not file
    paths — a frequent point of confusion ("I allowed `cat` but it's still denied",
    or "`cat /etc/passwd` passed"). Surface the verb-vs-path distinction inline so
    the user doesn't have to go re-read the policy comments.
    """
    spec = (cfg.get("enforce", {}) or {}).get(tool)
    if tool == "Bash" and isinstance(spec, str) and spec.strip().startswith("shlex:"):
        return (f"{reason} (the Bash allowlist authorizes the command *verb*, not file "
                "paths — add the verb to the shlex list if it's safe; filesystem scope "
                "comes from Read/Write/Edit)")
    return reason


def _receipt_fail_marker() -> Path:
    """Sidecar marker recording that the audit sink is unwritable.

    Persisted (not just an in-process flag) so `status`/`check` — separate
    processes from the per-call hook — can surface a broken audit trail.
    """
    return RECEIPTS.parent / ".receipt_write_failed"


def receipt_sink_failure() -> str | None:
    """Last recorded receipt-write failure detail, or None if the sink is healthy."""
    try:
        m = _receipt_fail_marker()
        return m.read_text().strip() if m.exists() else None
    except Exception:
        return None


def _canonical_receipt_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _receipt_signing_key():
    from tenuo import SigningKey

    ensure_state_dir()
    with _receipt_append_lock():
        if RECEIPT_KEY.exists():
            key = SigningKey.from_bytes(base64.b64decode(RECEIPT_KEY.read_text()))
            if not RECEIPT_PUB.exists():
                RECEIPT_PUB.write_text(key.public_key.to_bytes().hex())
            return key
        key = SigningKey.generate()
        write_secret(RECEIPT_KEY, base64.b64encode(bytes(key.secret_key_bytes())).decode())
        RECEIPT_PUB.write_text(key.public_key.to_bytes().hex())
        return key


def _trusted_receipt_signer() -> str | None:
    try:
        if RECEIPT_PUB.exists():
            return RECEIPT_PUB.read_text().strip()
        if RECEIPT_KEY.exists():
            key = _receipt_signing_key()
            return key.public_key.to_bytes().hex()
    except Exception:
        pass
    return None


def _last_receipt_hash() -> str | None:
    if not RECEIPTS.exists():
        return None
    try:
        for line in reversed(RECEIPTS.read_text().splitlines()):
            if not line.strip():
                continue
            row = json.loads(line)
            if isinstance(row, dict):
                return row.get("receipt_hash") or row.get("hash")
    except Exception:
        return None
    return None


def _unwrap_receipt(row: dict) -> dict:
    payload = row.get("payload")
    return payload if isinstance(payload, dict) else row


def _receipt_trust_roots() -> list[str]:
    """Trusted root public keys recorded outside the receipt itself."""
    roots: list[str] = []
    for path in (globals().get("ISSUER_PUB"),):
        try:
            if path and Path(path).exists():
                val = Path(path).read_text().strip()
                if val:
                    roots.append(val)
        except Exception:
            pass
    try:
        if STATE_JSON.exists():
            val = json.loads(STATE_JSON.read_text()).get("issuer_pub_hex")
            if isinstance(val, str) and val.strip():
                roots.append(val.strip())
    except Exception:
        pass
    try:
        val = load_cloud_state().get("root")
        if isinstance(val, str) and val.strip():
            roots.append(val.strip())
    except Exception:
        pass
    out = []
    seen = set()
    for root in roots:
        if root not in seen:
            seen.add(root)
            out.append(root)
    return out


def _verify_authz_evidence(payload: dict, idx: int) -> list[str]:
    """Replay the governed decision embedded in one receipt payload.

    Local replay validates the warrant chain, deterministic constraints, and
    presence of a recorded approval when the receipt evidence says approval was
    required. It does not reconstruct the Cloud approval policy or threshold;
    Cloud audit is the independent source for approver/threshold verification.
    """
    authz = payload.get("authz")
    if not isinstance(authz, dict) or not authz:
        return []

    errors: list[str] = []
    required = ("warrant_stack_b64", "warrant_stack_hash", "warrant_id",
                "tenuo_tool", "sign_args", "pop_b64")
    missing = [k for k in required if k not in authz or authz.get(k) is None]
    if missing:
        return [f"receipt {idx}: authz evidence missing {missing}"]

    try:
        from tenuo import Authorizer, PublicKey

        stack_b64 = authz["warrant_stack_b64"]
        stack_bytes = _decode_b64url_or_standard(stack_b64)
        stack_hash = hashlib.sha256(stack_bytes).hexdigest()
        if authz.get("warrant_stack_hash") != stack_hash:
            errors.append(f"receipt {idx}: warrant_stack_hash mismatch")
        chain = _decode_warrant_header(stack_b64)
        if not chain:
            return [*errors, f"receipt {idx}: empty warrant chain"]
        leaf = chain[-1]
        if authz.get("warrant_id") != leaf.id:
            errors.append(f"receipt {idx}: warrant_id mismatch")
        ids = authz.get("warrant_chain_ids")
        if isinstance(ids, list) and ids != [w.id for w in chain]:
            errors.append(f"receipt {idx}: warrant_chain_ids mismatch")

        roots = _receipt_trust_roots()
        if not roots:
            return [*errors, f"receipt {idx}: no trusted root key available for warrant verification"]

        from tenuo.exceptions import UntrustedRoot
        verified_root = None
        chain_errors: list[str] = []
        untrusted_root_error = None
        for pos, root in enumerate(roots):
            try:
                verifier = Authorizer()
                verifier.add_trusted_root(PublicKey.from_bytes(bytes.fromhex(root)))
                verifier.verify_chain(chain)
                verified_root = root
                break
            except UntrustedRoot as ute:
                untrusted_root_error = str(ute)
                chain_errors.append(f"root[{pos}] {root[:16]}...: root warrant untrusted")
            except Exception as exc:
                chain_errors.append(f"root[{pos}] {root[:16]}...: {exc}")
        if verified_root is None:
            detail = "; ".join(chain_errors) or "no roots checked"
            return [*errors, f"receipt {idx}: warrant chain invalid ({detail})"]

        verifier = Authorizer()
        verifier.add_trusted_root(PublicKey.from_bytes(bytes.fromhex(verified_root)))
        tool = authz["tenuo_tool"]
        args = authz["sign_args"]
        constraint_error = leaf.check_constraints(tool, args)
        in_bounds = constraint_error is None

        pop_ts = authz.get("pop_ts")
        pop_age = time.time() - pop_ts if isinstance(pop_ts, int) else None
        if pop_age is not None and pop_age < 0:
            errors.append(f"receipt {idx}: pop_ts is in the future")

        recorded = payload.get("decision")
        if recorded == "allow" and not in_bounds:
            errors.append(f"receipt {idx}: recorded allow but warrant replay denied ({constraint_error})")
        if recorded == "allow" and authz.get("approval_required") and not authz.get("approvals_b64"):
            errors.append(f"receipt {idx}: recorded allow but approval evidence missing")
    except Exception as exc:
        errors.append(f"receipt {idx}: authz evidence invalid ({exc})")
    return errors


def verify_receipt_rows(rows: list[dict]) -> tuple[bool, list[str]]:
    """Verify local receipt signatures, hash chain, and embedded authorization evidence."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:
        return False, [f"cryptography unavailable: {exc}"]

    errors: list[str] = []
    prev = None
    trusted_signer = _trusted_receipt_signer()
    if not trusted_signer:
        errors.append("receipt verifier key unavailable")
    for idx, row in enumerate(rows, 1):
        payload = row.get("payload")
        sig_b64 = row.get("signature")
        pub_hex = row.get("signer_pub")
        receipt_hash = row.get("receipt_hash")
        if not isinstance(payload, dict) or not sig_b64 or not pub_hex or not receipt_hash:
            errors.append(f"receipt {idx}: unsigned or malformed")
            continue
        if trusted_signer and pub_hex != trusted_signer:
            errors.append(f"receipt {idx}: signer_pub does not match trusted receipt key")
        if payload.get("prev_hash") != prev:
            errors.append(f"receipt {idx}: prev_hash mismatch")
        canonical = _canonical_receipt_bytes(payload)
        try:
            sig = base64.b64decode(sig_b64)
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            pub.verify(sig, canonical)
        except Exception as exc:
            errors.append(f"receipt {idx}: signature invalid ({exc})")
        expected = hashlib.sha256(canonical + base64.b64decode(sig_b64)).hexdigest()
        if receipt_hash != expected:
            errors.append(f"receipt {idx}: receipt_hash mismatch")
        errors.extend(_verify_authz_evidence(payload, idx))
        prev = receipt_hash
    return not errors, errors


def _path_label(path: Path) -> str:
    try:
        root = globals().get("DEMO_DIR")
        if root:
            return str(path.relative_to(root))
    except Exception:
        pass
    return str(path)


def receipt_verify_summary_lines(rows: list[dict], ok: bool = True) -> list[str]:
    """Human-readable explanation of what local receipt verification checked."""
    governed = any(isinstance(_unwrap_receipt(r).get("authz"), dict)
                   and _unwrap_receipt(r).get("authz") for r in rows)
    approval_gated = any(isinstance(_unwrap_receipt(r).get("authz"), dict)
                         and _unwrap_receipt(r).get("authz", {}).get("approval_required")
                         for r in rows)
    local_issuer = ISSUER_PUB.exists() or STATE_JSON.exists()
    cloud_state = globals().get("CLOUD_STATE")
    cloud_root = bool(cloud_state and Path(cloud_state).exists())
    mark = "ok" if ok else "!!"

    lines = [
        "",
        "Verification checks:",
        f"  {mark} receipt signatures     Ed25519 over canonical payload; signer={_path_label(RECEIPT_PUB)}",
        f"  {mark} hash chain             prev_hash links every receipt",
    ]
    if governed:
        lines.extend([
            f"  {mark} warrant binding        warrant id + warrant stack hash in governed receipts",
            f"  {mark} warrant chain          checked against trusted warrant root(s)",
            f"  {mark} decision replay        recorded allow/deny matches warrant constraints",
        ])
        if approval_gated:
            lines.append(f"  {mark} approval presence     approval-gated allows include approval evidence")
    else:
        lines.append("  .. warrant replay         no governed receipt evidence in this log")

    lines.extend(["", "Trust roots:"])
    lines.append(f"  receipt signer            {_path_label(RECEIPT_PUB)}")
    if local_issuer:
        lines.append(f"  warrant root              local issuer {_path_label(ISSUER_PUB)}")
    if cloud_root:
        lines.append(f"  warrant root              cloud tenant root {_path_label(Path(cloud_state))}")
    if not local_issuer and not cloud_root:
        lines.append("  warrant root              <none found>")

    lines.extend(["", "Trust model:"])
    if cloud_root:
        lines.append("  Cloud root present: warrant authority chains to the tenant root.")
    else:
        lines.append("  Local mode: evidence is tamper-evident relative to local .state keys.")
        lines.append("  For production evidence, anchor signer/root outside the agent machine or use Cloud.")
    return lines


@contextlib.contextmanager
def _receipt_append_lock():
    """Serialize the read-prev-hash + append across every receipt writer.

    Receipts are written by multiple processes: each native-tool PreToolUse hook
    is a fresh short-lived process, and the long-running MCP proxy writes too.
    Without a lock, two writers both read the same `prev_hash` and append rows
    claiming it — forking the hash chain and producing spurious `audit --verify`
    failures — and large rows (an embedded warrant stack can exceed PIPE_BUF) can
    tear. An exclusive advisory lock on a sidecar file makes the whole
    read-modify-append atomic. On platforms without ``fcntl`` (notably Windows)
    this degrades to a no-op and assumes a single local receipt writer; use Cloud
    audit export or avoid concurrent local hooks if strict local hash-chain
    continuity matters there.
    """
    if fcntl is None:
        yield
        return
    lock_path = RECEIPTS.with_name(RECEIPTS.name + ".lock")
    with open(lock_path, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


def write_receipt(entry: dict) -> bool:
    """Append one receipt to the signed decision log. Returns True on success.

    Returns False if the audit sink is unwritable (disk full, bad permissions) and
    drops a marker so `status`/`check` can surface it — a SILENT gap in the audit
    trail is the worst failure mode for an audit product. In enforce mode, callers
    fail closed on a False return when `strict_receipts: true` is set in policy.

    The chain link (`prev_hash`) is read and the row appended under an exclusive
    lock so concurrent hook/proxy writers can't fork the chain or interleave.
    """
    global _receipt_write_warned
    try:
        ensure_state_dir()
        key = _receipt_signing_key()
        with _receipt_append_lock():
            payload = dict(entry)
            payload["ts"] = datetime.now(timezone.utc).isoformat()
            payload["receipt_version"] = 1
            payload["prev_hash"] = _last_receipt_hash()
            canonical = _canonical_receipt_bytes(payload)
            sig = key.sign_raw(canonical)
            row = {
                "payload": payload,
                "signer_pub": key.public_key.to_bytes().hex(),
                "signature": base64.b64encode(sig).decode(),
                "receipt_hash": hashlib.sha256(canonical + sig).hexdigest(),
            }
            with RECEIPTS.open("a") as fh:
                fh.write(json.dumps(row) + "\n")
                fh.flush()
        marker = _receipt_fail_marker()
        if marker.exists():
            marker.unlink()  # sink recovered
        return True
    except Exception as exc:
        try:
            _receipt_fail_marker().write_text(f"{datetime.now(timezone.utc).isoformat()} {exc}")
        except Exception:
            pass
        if not _receipt_write_warned:
            _receipt_write_warned = True
            print(f"warning: could not write receipt to {RECEIPTS}: {exc}",
                  file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Internal entrypoints: Claude hooks + MCP proxy
# ---------------------------------------------------------------------------


def cmd_hook(_args) -> None:
    # FAIL-CLOSED GUARD. Claude Code treats hook exit code 2 as "block", but
    # any other non-zero exit (e.g. an unhandled traceback -> exit 1) is a
    # NON-blocking error and the tool call PROCEEDS. A crash here would be a
    # full bypass, so every internal error must end as an explicit deny
    # decision (exit 0 + JSON) — verified empirically against claude 2.1.x.
    decision, reason_text = "deny", "Tenuo hook internal error (fail-closed)"
    tool, agent_type, audit_only = "", None, False
    try:
        cfg = load_config()
        apply_transport_env(cfg)
        audit_only = is_audit_mode(cfg)
        try:
            event = json.loads(sys.stdin.read() or "{}")
        except json.JSONDecodeError:
            event = {}
        tool = event.get("tool_name", "")
        tin = event.get("tool_input", {}) or {}
        # `agent_type` is populated by Claude Code ONLY when the call originates
        # inside a subagent (it's the subagent's frontmatter name). Main-thread
        # calls have no agent_type and run under the session warrant as usual.
        agent_type = event.get("agent_type")
        roles = subagent_roles(cfg)
        # Enforce mode drives the live approval flow; audit mode only reports.
        allowed, reason, governed, tenuo_tool, authz_evidence = (
            authorize_call(cfg, tool, tin, agent_type, roles, live=not audit_only,
                           return_context=True))
        wrote = write_receipt(
            {"phase": "pre", "decision": "allow" if allowed else "deny",
             "shadow": audit_only, "claude_tool": tool, "tenuo_tool": tenuo_tool,
             "governed": governed, "agent_type": agent_type, "args": tin,
             "reason": reason, "authz": authz_evidence}
        )
        kind = "authorized" if governed else "audited"
        scope = f" (subagent:{agent_type})" if agent_type else ""
        decision = "allow" if allowed else "deny"
        if allowed:
            # Include approval outcome in the hook reason when relevant.
            extra = f" — {reason}" if "approv" in (reason or "").lower() else ""
            reason_text = f"Tenuo {kind}: {tool}{scope}{extra}"
        else:
            reason_text = f"Tenuo denied {tool}{scope}: {reason}"
        # strict_receipts: an allow whose audit receipt couldn't be written is an
        # ungoverned action in an audit product — fail closed (enforce mode only).
        if decision == "allow" and not audit_only and not wrote and cfg.get("strict_receipts"):
            decision = "deny"
            reason_text = (f"Tenuo denied {tool}{scope}: audit receipt unwritable and "
                           "strict_receipts is on (fail-closed)")
    except (Exception, SystemExit) as exc:
        # Always leave a signal: a silent failure with no receipt would be zero
        # governance AND zero observability (e.g. authorizer down, missing deps).
        write_receipt({"phase": "pre", "decision": decision, "shadow": audit_only,
                       "claude_tool": tool, "agent_type": agent_type,
                       "error": str(exc), "reason": f"hook error: {exc}"})
        reason_text = f"Tenuo hook error (fail-closed): {exc}"
    if audit_only:
        # Observe-only is NEUTRAL: print no permissionDecision at all, so Claude's
        # own permission system stays fully in effect. Emitting "allow" here would
        # auto-approve every call and BYPASS the user's permission prompts — i.e.
        # observe-only would be MORE permissive than having no hook. The receipt
        # above already records what enforcement would have decided (shadow:true).
        return
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": decision,
        "permissionDecisionReason": reason_text}}))


def cmd_managed_hook(args) -> None:
    """MDM-pinned PreToolUse entrypoint: identical to ``_hook`` but enforcement is
    anchored in the managed artifact, not in editable local state.

    Sets ``TENUO_MANAGED_ENFORCE`` so the posture floor applies (managed_mode →
    never observe-only) even if a developer edited ``tenuo.yaml`` to ``mode:
    dry-run`` or removed ``cloud.managed`` / the cloud-state flag. The allow/deny
    itself still comes from the Cloud-root-only authorizer, so with no valid Cloud
    warrant the call is denied (fail-closed). Wired by `managed_claude_settings`.
    """
    os.environ["TENUO_MANAGED_ENFORCE"] = "1"
    cmd_hook(args)


def cmd_managed_mcp_proxy(args) -> None:
    """MDM-pinned MCP proxy entrypoint: like ``_mcp-proxy`` but enforcement is
    anchored in the managed artifact, not in editable local state.

    MCP is a primary enforcement surface, so the same downgrade vector as the
    hook applies: without this, a developer who set ``mode: dry-run`` and dropped
    the managed flag would make the proxy FORWARD denied MCP calls. Setting
    ``TENUO_MANAGED_ENFORCE`` forces enforce regardless. Wired by `managed_mcp_config`.
    """
    os.environ["TENUO_MANAGED_ENFORCE"] = "1"
    cmd_mcp_proxy(args)


def cmd_post(_args) -> None:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        event = {}
    resp = event.get("tool_response", event.get("tool_result", ""))
    write_receipt({"phase": "post", "claude_tool": event.get("tool_name", ""),
                   "agent_type": event.get("agent_type"),
                   "outcome_preview": json.dumps(resp)[:240] if resp is not None else ""})


def mcp_proxy_decision(allowed: bool, reason: str, audit_only: bool, name: str):
    """Map an authorize_call result to a proxy action. Returns (forward, message).

    `forward=True` → pass the call to the downstream MCP server; `message` is None.
    `forward=False` → return `message` to the client as an MCP error; do NOT forward.

    Observe-only (`audit_only`) never blocks — it always forwards (the caller logs
    WOULD-DENY). Human-in-the-loop is just the deny branch resolving slowly: by the
    time this is called, authorize_call has already blocked on the Cloud approval
    poll, so `allowed` reflects the approver's decision. We split that branch in two
    so the agent can tell an approval outcome (pending / timed out / declined) from
    a hard policy deny: all approval outcomes share the "did NOT run" framing and
    carry the specific reason, so the agent can re-try a pending/timed-out call once
    approved while treating a declined one as terminal — whereas a hard deny means
    the action is simply not permitted. The reason prefix that marks the approval
    family is APPROVAL_PENDING_REASON (matched the same way as elsewhere, via
    startswith).
    """
    if allowed or audit_only:
        return True, None
    if reason and reason.startswith(APPROVAL_PENDING_REASON):
        return False, f"Tenuo: {name} not run — {reason}"
    return False, f"Tenuo denied {name}: {reason}"


def cmd_mcp_proxy(_args) -> None:
    import asyncio

    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent

    cfg = load_config()
    apply_transport_env(cfg)
    mcp_cfg = cfg.get("mcp", {})
    downstream = str((DEMO_DIR / mcp_cfg.get("downstream", "")).resolve())
    enforced = mcp_enforce_entries(cfg)
    catchall = catchall_cap(cfg)
    audit_only = is_dry_run_mode(cfg)
    roles = subagent_roles(cfg)

    def log(m):
        print(f"[tenuo-mcp-proxy] {m}", file=sys.stderr, flush=True)

    async def run():
        params = StdioServerParameters(command=sys.executable, args=[downstream])
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
                    # HiTL note: authorize_call routes governed calls through
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
                    allowed, reason, _, tenuo_tool, authz_evidence = await asyncio.to_thread(
                        authorize_call, cfg, name, tin, None, roles,
                        live=not audit_only, return_context=True)
                    wrote = write_receipt({"phase": "pre", "source": "mcp_proxy",
                                   "decision": "allow" if allowed else "deny",
                                   "shadow": audit_only, "claude_tool": name,
                                   "tenuo_tool": tenuo_tool,
                                   "args": tin, "reason": reason,
                                   "authz": authz_evidence})
                    # strict_receipts: don't forward an allowed call we couldn't log.
                    if allowed and not audit_only and not wrote and cfg.get("strict_receipts"):
                        allowed, reason = False, "audit receipt unwritable, strict_receipts on (fail-closed)"
                    forward, message = mcp_proxy_decision(allowed, reason, audit_only, name)
                    if not forward:
                        log(f"DENY {name}: {reason}")
                        return [TextContent(type="text", text=message)]
                    if not allowed:
                        log(f"WOULD-DENY {name} (observe-only, forwarding): {reason}")
                    return (await down.call_tool(name, tin)).content

                async with stdio_server() as (r, w):
                    await proxy.run(r, w, proxy.create_initialization_options())

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Generation: warrant, gateway, Claude wiring
# ---------------------------------------------------------------------------


def enforced_capabilities(cfg: dict) -> dict:
    """Capability -> {field: constraint} for everything `enforce`d.

    Unifies native tools, MCP tools, and — when `subagents:` is declared — the
    synthetic `spawn_agent` capability (subagent_type constrained to a oneof of
    the declared roles). De-duplicated: a capability shared by a native and an
    MCP tool (e.g. read_file) yields one entry.
    """
    from tenuo import OneOf
    from tenuo_core import Wildcard

    sandbox = cfg["_sandbox_abs"]
    # Relax an approval-gated tool's constraints ONLY when a Cloud trigger will
    # actually carry the gate (use_cloud_trigger, not trigger_id alone). A stale
    # trigger_id with no creds would otherwise mint the wildcard locally with no gate
    # (fail-open). Evaluated lazily, only when an approval gate is actually present.
    gate_web = bool(webfetch_approval(cfg) and use_cloud_trigger(cfg))
    caps: dict = {}
    for g in governed_map(cfg).values():
        if g["cap"] in caps:
            continue
        if "web" in g:
            caps[g["cap"]] = make_web_constraints(g["web"], approval_gate=gate_web)
        elif g.get("approval"):
            # Cloud human-approval gate on this tool's arg (mirrors mcp.enforce
            # approval): the arg relaxes to a wildcard and the gate itself lives in
            # the Cloud trigger warrant. Local minting has no approval, so the cap
            # is granted only under a trigger; without Cloud it stays denied.
            if use_cloud_trigger(cfg):
                caps[g["cap"]] = {g["arg"]: Wildcard()}
        else:
            caps[g["cap"]] = {g["arg"]: make_constraint(g["spec"], sandbox)}
    for mtool, raw in (cfg.get("mcp", {}).get("enforce") or {}).items():
        if mtool in caps:
            continue
        parsed = parse_mcp_enforce_spec(raw)
        cons = parsed["constraints"]
        if cons:
            caps[mtool] = {a: make_constraint(spec, sandbox) for a, spec in cons.items()}
        elif parsed.get("approval"):
            # `exempt_args` are the constrained argument values that skip a human
            # approval. Cloud trigger warrants wildcard the gated arg so the
            # authorizer can reach the approval gate; local warrants cannot carry
            # that gate, so they grant only the exempt values and deny the rest.
            exempt = parsed.get("exempt_args") or {}
            if use_cloud_trigger(cfg):
                gated = list(exempt.keys()) or [mcp_default_arg(mtool)]
                caps[mtool] = {a: Wildcard() for a in gated}
            elif exempt:
                caps[mtool] = {a: make_constraint(spec, sandbox) for a, spec in exempt.items()}
    roles = subagent_roles(cfg)
    if roles:
        # Spawning is a first-class signed capability; per-role child warrants
        # drop it (with_tools), so a subagent can't spawn further subagents.
        caps[SPAWN_CAP] = {"subagent_type": OneOf(list(roles.keys()))}
    return caps


def warrant_capabilities() -> dict | None:
    """Capabilities granted by the active session warrant, as {cap: constraints}.

    Returns None when no readable warrant is on disk (so callers can distinguish
    "warrant grants nothing" from "we can't tell"). The session warrant file holds
    a single warrant (Cloud-issued in managed mode, locally-minted otherwise);
    subagent stacks live in separate files.
    """
    if not WARRANT.exists():
        return None
    try:
        from tenuo import Warrant
        return Warrant.from_base64(WARRANT.read_text()).capabilities or {}
    except Exception:
        return None


def local_widened_tools(cfg: dict, granted: dict | None) -> list[str]:
    """Tools the LOCAL policy governs that the granted warrant does NOT include.

    Local attenuation may narrow the warrant (govern a subset, tighten
    constraints) but must never widen it. In managed Cloud mode the warrant is
    the authority, so any "extra" local tool is inert: the authorizer denies it
    because no such capability was granted. We surface it so an operator isn't
    misled into thinking a local edit took effect.

    Comparison is by capability NAME (tool-level); the synthetic /gate catch-all
    capabilities are excluded since they are routing artifacts, not grants.
    Constraint-level intersection (narrowing within a shared tool) is a separate,
    future layer — this is the tool-addition guard.
    """
    if granted is None:
        return []
    synthetic = {CATCHALL_AUDIT, CATCHALL_DENY}
    local = (set(enforced_capabilities(cfg).keys())
             | set(audit_map(cfg).values())) - synthetic
    return sorted(local - set(granted.keys()))


def write_gateway(cfg: dict, enforced_caps: dict) -> None:
    """Write the authorizer's gateway config (routes + tool decls) from policy.

    A pure generated artifact (no keys), so it's safe to refresh on every `up` —
    that keeps routes aligned with tenuo.yaml even for Cloud-issued warrants.
    """
    import yaml

    audit = audit_map(cfg)
    tools, routes = {}, []
    for cap, cons in enforced_caps.items():
        tools[cap] = {"description": cap, "constraints": {}}
        routes.append({"pattern": f"/verify/{cap}", "method": ["POST"], "tool": cap,
                       "constraints": {f: {"from": "body", "path": f, "required": True}
                                       for f in cons}})
    for cap in audit.values():
        if cap in tools:
            continue
        tools[cap] = {"description": cap, "constraints": {}}
        routes.append({"pattern": f"/verify/{cap}", "method": ["POST"], "tool": cap,
                       "constraints": {}})
    for mtool, parsed in mcp_enforce_entries(cfg).items():
        if mtool in tools:
            continue
        fields = mcp_constraint_args(mtool, parsed)
        if not fields:
            continue
        tools[mtool] = {"description": mtool, "constraints": {}}
        routes.append({"pattern": f"/verify/{mtool}", "method": ["POST"], "tool": mtool,
                       "constraints": {f: {"from": "body", "path": f, "required": True}
                                       for f in fields}})
    # Catch-all route /gate -> the granted "audit" or the ungranted "unlisted"
    # capability (declared as a tool either way so the route compiles).
    catchall = catchall_cap(cfg)
    tools.setdefault(catchall, {"description": catchall, "constraints": {}})
    # Under `default: approve` the catch-all carries a whole-tool approval gate. The
    # gate fires regardless of args, but the /gate route still extracts `tool` so the
    # approval's request_hash binds per tool name (resolve_tool signs the same field).
    gate_constraints = ({"tool": {"from": "body", "path": "tool", "required": True}}
                        if default_mode(cfg) == "approve" else {})
    routes.append({"pattern": "/gate", "method": ["POST"], "tool": catchall,
                   "constraints": gate_constraints})
    gw = {"version": "1",
          "settings": {"debug_mode": True, "warrant_header": WARRANT_HEADER,
                       "pop_header": POP_HEADER, "clock_tolerance_secs": 30},
          "tools": tools, "routes": routes}
    GATEWAY.write_text(yaml.safe_dump(gw, sort_keys=False))
    sync_authorizer_mount()


def mint_local_warrant(cfg: dict, issuer, holder):
    """Mint a session warrant from tenuo.yaml with the given keys."""
    from tenuo import Warrant

    builder = Warrant.mint_builder()
    enforced = enforced_capabilities(cfg)
    for cap, cons in enforced.items():
        builder = builder.capability(cap, cons)
    # Mirror write_gateway: audit caps must not overwrite enforced constraints
    # (mint builder is last-wins on duplicate tool names).
    for cap in audit_map(cfg).values():
        if cap not in enforced:
            builder = builder.capability(cap, {})
    # Catch-all is never granted locally: unlisted tools are always denied. Local
    # minting has no approval support, so `default: approve` can't be honored here
    # and falls back to deny (the runtime surfaces that as an advisory). Cloud
    # trigger warrants are where `approve` grants the gated catch-all.
    return builder.holder(holder.public_key).ttl(session_ttl_seconds(cfg)).mint(issuer)


def remint_session(cfg: dict) -> str:
    """Re-mint the local session warrant REUSING the existing issuer + holder.

    Because the issuer key is unchanged, the running authorizer's trust anchor
    still applies — no container restart needed (the warrant itself rides in
    every request header). Used to self-heal an expired warrant on `up`.
    """
    from tenuo import SigningKey

    issuer = SigningKey.from_bytes(base64.b64decode(ISSUER_KEY.read_text()))
    holder = SigningKey.from_bytes(base64.b64decode(HOLDER_KEY.read_text()))
    warrant = mint_local_warrant(cfg, issuer, holder)
    write_secret(WARRANT, warrant.to_base64())
    update_state_warrant_id(warrant.id)
    return warrant.id


def update_state_warrant_id(wid: str) -> None:
    """Keep state.json's warrant_id in sync after a re-mint / trigger re-fire."""
    try:
        st = json.loads(STATE_JSON.read_text()) if STATE_JSON.exists() else {}
        st["warrant_id"] = wid
        STATE_JSON.write_text(json.dumps(st, indent=2))
    except Exception:
        pass


def sync_runtime_artifacts(cfg: dict | None = None, *, restart_authorizer: bool = False) -> bool:
    """Regenerate hook/MCP wiring, gateway routes, and subwarrants from tenuo.yaml.

    Does not re-mint or re-fire the session warrant. When ``restart_authorizer``
    is set and the authorizer is up, reloads it so new routes take effect.
    """
    cfg = cfg or load_config()
    write_claude_wiring(cfg)
    write_gateway(cfg, enforced_capabilities(cfg))
    refresh_subwarrants(cfg)
    harden_state_permissions()
    if restart_authorizer and authorizer_running(cfg):
        empty = argparse.Namespace()
        cmd_down(empty)
        cmd_up(empty)
        return True
    return False


def refresh_policy(cfg: dict | None = None) -> str:
    """Re-read tenuo.yaml into runtime artifacts (wiring, gateway, warrant, subwarrants).

    Local mode re-mints the session warrant from policy. Cloud trigger mode re-fires
    the trigger (capabilities still come from the trigger config — run `tenuo-admin
    setup` first when enforce/audit/subagent policy changed on Cloud).
    """
    cfg = cfg or load_config()
    creds = cloud_creds(cfg)
    use_trigger = use_cloud_trigger(cfg)
    _assert_managed_runtime(cfg, use_trigger)

    write_claude_wiring(cfg)
    write_gateway(cfg, enforced_capabilities(cfg))

    if use_trigger:
        warrant_b64, _root = fire_session_warrant(cfg, creds)
        _record_fired_warrant(warrant_b64)
        from tenuo import Warrant
        wid = Warrant.from_base64(warrant_b64).id
    elif ISSUER_KEY.exists() and HOLDER_KEY.exists():
        if not WARRANT.exists():
            raise SystemExit("Run `tenuo-claude init` first.")
        wid = remint_session(cfg)
    else:
        raise SystemExit("Run `tenuo-claude init` first.")

    refresh_subwarrants(cfg)
    harden_state_permissions()
    return wid


def _is_tenuo_hook(hook: dict, subcommand: str) -> bool:
    """True when a hook entry belongs to Tenuo (matches our command string).

    Hook entries have the shape ``{"matcher": ..., "hooks": [{"command": ...}]}``.
    The command lives one level deeper, inside the nested ``hooks`` list.
    """
    for inner in hook.get("hooks") or []:
        cmd = inner.get("command", "")
        if wiring_command_string(subcommand) in cmd or f" {subcommand}" in cmd:
            return True
    return False


def _merge_hook_list(existing: list, tenuo_entry: dict, subcommand: str) -> list:
    """Replace the existing Tenuo hook entry in-place; append if absent.

    Preserves all non-Tenuo hooks at their original positions.
    """
    merged = [h for h in existing if not _is_tenuo_hook(h, subcommand)]
    merged.append(tenuo_entry)
    return merged


def write_claude_wiring(cfg: dict) -> None:
    """Merge Tenuo hooks into .claude/settings.json and Tenuo server into .mcp.json.

    Only Tenuo-owned entries are added or updated; all other keys (permissions,
    other hooks, other MCP servers) are left untouched.  Re-run ``init`` /
    ``refresh`` after moving the repo or changing the install path.
    """
    claude_dir = DEMO_DIR / ".claude"
    claude_dir.mkdir(exist_ok=True)
    hook_timeout = APPROVAL_POLL_SECONDS + 30 if has_approval_gates(cfg) else 30

    settings_path = claude_dir / "settings.json"
    try:
        settings = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    except (json.JSONDecodeError, OSError):
        settings = {}
    if not isinstance(settings, dict):
        settings = {}

    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        settings["hooks"] = hooks

    hooks["PreToolUse"] = _merge_hook_list(
        hooks.get("PreToolUse") or [],
        {"matcher": "*", "hooks": [
            {"type": "command", "command": hook_wiring_command_string("_hook"),
             "timeout": hook_timeout}]},
        "_hook",
    )
    hooks["PostToolUse"] = _merge_hook_list(
        hooks.get("PostToolUse") or [],
        {"matcher": "*", "hooks": [
            {"type": "command", "command": wiring_command_string("_post")}]},
        "_post",
    )
    settings_path.write_text(json.dumps(settings, indent=2))

    mcp_path = DEMO_DIR / ".mcp.json"
    desired = mcp_wiring(cfg)
    if desired:
        try:
            existing_mcp = json.loads(mcp_path.read_text()) if mcp_path.exists() else {}
        except (json.JSONDecodeError, OSError):
            existing_mcp = {}
        if not isinstance(existing_mcp, dict):
            existing_mcp = {}
        servers = existing_mcp.setdefault("mcpServers", {})
        servers.update(desired["mcpServers"])
        mcp_path.write_text(json.dumps(existing_mcp, indent=2) + "\n")
    elif mcp_path.exists():
        # Remove only the Tenuo server; leave any other MCP servers intact.
        try:
            existing_mcp = json.loads(mcp_path.read_text())
        except (json.JSONDecodeError, OSError):
            existing_mcp = {}
        if isinstance(existing_mcp, dict):
            existing_mcp.get("mcpServers", {}).pop(MCP_SERVER_NAME, None)
            if existing_mcp.get("mcpServers") == {}:
                existing_mcp.pop("mcpServers", None)
            if existing_mcp:
                mcp_path.write_text(json.dumps(existing_mcp, indent=2) + "\n")
            else:
                mcp_path.unlink()


def remove_claude_wiring() -> list[str]:
    """Reverse of ``write_claude_wiring``: strip Tenuo's hooks from
    ``.claude/settings.json`` and Tenuo's MCP server from ``.mcp.json``.

    Only Tenuo-owned entries are removed; any other hooks, MCP servers, or keys
    the user added are preserved. Files that become empty are deleted so a later
    ``init`` starts from a clean slate. Returns a list of human-readable lines
    describing what changed (empty when nothing was wired).
    """
    changed: list[str] = []
    settings_path = DEMO_DIR / ".claude" / "settings.json"
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            settings = None
        if isinstance(settings, dict) and isinstance(settings.get("hooks"), dict):
            hooks = settings["hooks"]
            removed = False
            for event, sub in (("PreToolUse", "_hook"), ("PostToolUse", "_post")):
                entries = hooks.get(event)
                if not isinstance(entries, list):
                    continue
                kept = [h for h in entries if not _is_tenuo_hook(h, sub)]
                if len(kept) != len(entries):
                    removed = True
                if kept:
                    hooks[event] = kept
                else:
                    hooks.pop(event, None)
            if not hooks:
                settings.pop("hooks", None)
            if removed:
                if settings:
                    settings_path.write_text(json.dumps(settings, indent=2))
                    changed.append("unwired Tenuo hooks from .claude/settings.json")
                else:
                    settings_path.unlink()
                    changed.append("removed .claude/settings.json (no other config)")

    mcp_path = DEMO_DIR / ".mcp.json"
    if mcp_path.exists():
        try:
            existing_mcp = json.loads(mcp_path.read_text())
        except (json.JSONDecodeError, OSError):
            existing_mcp = None
        if isinstance(existing_mcp, dict) and \
                MCP_SERVER_NAME in (existing_mcp.get("mcpServers") or {}):
            existing_mcp["mcpServers"].pop(MCP_SERVER_NAME, None)
            if existing_mcp.get("mcpServers") == {}:
                existing_mcp.pop("mcpServers", None)
            if existing_mcp:
                mcp_path.write_text(json.dumps(existing_mcp, indent=2) + "\n")
                changed.append(f"removed the {MCP_SERVER_NAME} server from .mcp.json")
            else:
                mcp_path.unlink()
                changed.append("removed .mcp.json (no other servers)")
    return changed


def ensure_state_dir() -> None:
    """Create .state as an owner-only (0700) directory, tightening it even if it
    already exists. It holds the holder/issuer signing keys and cloud
    credentials, so it must not be group/world-readable."""
    STATE.mkdir(parents=True, exist_ok=True)
    try:
        STATE.chmod(0o700)
    except OSError:
        pass


def write_secret(path, text: str) -> None:
    """Write a secret file (private key, cloud credential) as owner-only 0600.

    Mirrors write_admin_env's handling. The holder key signs every PoP — leaving
    it world-readable (the default 0644) lets any local user mint authorizations
    against the warrant, so secrets are never written at the default mode."""
    path.write_text(text)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _secret_paths() -> list[Path]:
    """Paths under .state that must be owner-only (0600)."""
    paths: list[Path] = []
    for name in ("holder_key.b64", "issuer_key.b64", "cloud.env", "warrant.b64"):
        p = STATE / name
        if p.exists():
            paths.append(p)
    paths.extend(STATE.glob("subwarrant_*.b64"))
    paths.extend(STATE.glob("cloud*.env"))
    return paths


def harden_state_permissions() -> None:
    """Tighten .state to 0700 and secret files to 0600 (idempotent)."""
    ensure_state_dir()
    for path in _secret_paths():
        try:
            path.chmod(0o600)
        except OSError:
            pass


def check_state_permissions() -> tuple[bool, list[str]]:
    """Return (ok, issues) for .state and secret file modes."""
    issues: list[str] = []
    if not STATE.exists():
        return True, issues
    mode = STATE.stat().st_mode & 0o777
    if mode != 0o700:
        issues.append(f".state is {oct(mode)} (want 0o700)")
    for path in _secret_paths():
        fmode = path.stat().st_mode & 0o777
        if fmode != 0o600:
            issues.append(f"{path.name} is {oct(fmode)} (want 0o600)")
    return not issues, issues


def authorizer_mount_dir() -> Path:
    """Host directory mounted into the authorizer container (gateway + SRL only)."""
    return STATE / "authorizer"


def sync_authorizer_mount() -> None:
    """Stage gateway (+ optional SRL) for Docker. Private keys stay on the host."""
    import shutil

    ensure_state_dir()
    mount = authorizer_mount_dir()
    mount.mkdir(exist_ok=True)
    # World-traversable, not secret: the authorizer container runs as a non-root
    # user and must read gateway.yaml via the bind mount (CI runners included).
    try:
        mount.chmod(0o755)
    except OSError:
        pass
    if not GATEWAY.exists():
        return
    dest = mount / GATEWAY.name
    shutil.copy2(GATEWAY, dest)
    try:
        dest.chmod(0o644)
    except OSError:
        pass
    srl_dest = mount / SRL.name
    if SRL.exists():
        shutil.copy2(SRL, srl_dest)
        try:
            srl_dest.chmod(0o644)
        except OSError:
            pass
    elif srl_dest.exists():
        srl_dest.unlink()

def generate(cfg: dict) -> dict:
    from tenuo import SigningKey

    ensure_state_dir()
    sandbox = cfg["_sandbox_abs"]
    Path(sandbox).mkdir(parents=True, exist_ok=True)

    issuer = SigningKey.generate()
    # REUSE an existing holder key: `tenuo-admin setup` claims this key with the
    # Cloud agent, and a Cloud-issued warrant binds to it (PoP). Regenerating it
    # on re-init would silently break every cloud-issued warrant until the agent
    # key is rotated and re-claimed.
    if HOLDER_KEY.exists():
        holder = SigningKey.from_bytes(base64.b64decode(HOLDER_KEY.read_text()))
    else:
        holder = SigningKey.generate()
        write_secret(HOLDER_KEY, base64.b64encode(bytes(holder.secret_key_bytes())).decode())
    warrant = mint_local_warrant(cfg, issuer, holder)

    write_secret(ISSUER_KEY, base64.b64encode(bytes(issuer.secret_key_bytes())).decode())
    ISSUER_PUB.write_text(issuer.public_key.to_bytes().hex())
    write_secret(WARRANT, warrant.to_base64())

    write_gateway(cfg, enforced_capabilities(cfg))

    STATE_JSON.write_text(json.dumps({
        "name": cfg.get("name", "tenuo-claude"), "warrant_id": warrant.id,
        "issuer_pub_hex": issuer.public_key.to_bytes().hex(), "sandbox": sandbox,
        "authorizer_url": AUTHZ_URL}, indent=2))

    write_claude_wiring(cfg)
    harden_state_permissions()
    return {"warrant_id": warrant.id, "issuer_pub": issuer.public_key.to_bytes().hex(),
            "sandbox": sandbox}


# ---------------------------------------------------------------------------
# Authorizer lifecycle
# ---------------------------------------------------------------------------


def fetch_tenant_root(url: str, api_key: str):
    try:
        req = urllib.request.Request(url + "/v1/revocations/srl/signed",
                                     headers={"Authorization": f"Bearer {api_key}"})
        with urllib.request.urlopen(req, timeout=8, context=_https_context()) as resp:
            issuer_b64 = json.loads(resp.read().decode())["payload"]["Issuer"]
            return base64.b64decode(issuer_b64).hex()
    except Exception:
        return None


def root_from_warrant_issuer(warrant_b64: str) -> str | None:
    """Best-effort Cloud trust anchor fallback when no signed SRL exists yet."""
    try:
        from tenuo import Warrant
        issuer = Warrant.from_base64(warrant_b64).issuer
        return issuer.to_bytes().hex()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tenuo Cloud: triggers (Cloud-issued, root-signed warrants)
# ---------------------------------------------------------------------------


def _https_context():
    """TLS context for Cloud calls, preferring certifi's CA bundle when present.

    macOS python.org framework builds ship without a CA store wired up, which
    makes every https call die with CERTIFICATE_VERIFY_FAILED. certifi rides in
    with the `tenuo` install, so use it when available; otherwise fall back to
    the system default context.
    """
    import ssl
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def cloud_api(method: str, cloud_url: str, key: str, path: str, body=None):
    """Call the Cloud control plane. Returns (status, parsed_json|text).

    Network/TLS failures return (0, <readable message>) instead of raising, so
    callers fail with one clear line rather than an urllib traceback.
    """
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        cloud_url.rstrip("/") + path, data=data, method=method,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_https_context()) as resp:
            raw = resp.read().decode() or "{}"
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode() or ""
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, raw
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        hint = ""
        if "CERTIFICATE_VERIFY_FAILED" in str(reason):
            hint = (" — this Python has no usable CA store; `pip install certifi` "
                    "(bundled with `tenuo`) or set SSL_CERT_FILE to a CA bundle")
        return 0, f"network error reaching {cloud_url}: {reason}{hint}"


ADMIN_KEY_VARS = ("TENUO_ADMIN_KEY", "TENUO_ADMIN_API_KEY")


def assert_no_admin_key() -> None:
    """Separation of duties: the runtime/agent plane must NEVER carry a tenant-admin
    API key. Admin actions (create agent/trigger) live in `tenuo-admin` with
    their own out-of-tree key (~/.tenuo/admin.env).

    Fail closed if an admin key is reachable from the runtime environment or
    leaks into .state/cloud.env — that would let a compromised session escalate.
    """
    reach = runtime_env()
    for var in ADMIN_KEY_VARS:
        if reach.get(var):
            raise SystemExit(
                f"Refusing to run: {var} is present in the runtime environment.\n"
                "Admin credentials must not reach the agent/runtime plane.\n"
                "Move it to ~/.tenuo/admin.env and run admin actions via `tenuo-admin`.")


def cloud_creds(cfg: dict) -> dict:
    """Resolve Cloud URL + the runtime authorizer key from cfg + .state/cloud.env.

    Accepts either ``TENUO_CONNECT_TOKEN`` (Quick Connect) or explicit
    ``TENUO_CONTROL_PLANE_URL`` + ``TENUO_API_KEY``. Explicit vars win when set.

    Note: no admin key here by design — runtime fires triggers and consumes
    warrants with the Quick Connect / authorizer service-account key only.
    See `tenuo-admin` / tenuo_claude_code.admin.
    """
    env = runtime_env()
    url = (cfg.get("cloud") or {}).get("url") or env.get("TENUO_CONTROL_PLANE_URL")
    api_key = env.get("TENUO_API_KEY")
    connect = env.get("TENUO_CONNECT_TOKEN")
    if connect:
        parsed = _parse_connect_token(connect)
        url = url or parsed["url"]
        api_key = api_key or parsed["api_key"]
    return {
        "url": url,
        "api_key": api_key,
        "root": env.get("TENUO_TENANT_ROOT"),
    }


# ---------------------------------------------------------------------------
# Onboarding helpers (check / onboard / bootstrap / cloud profile)
# ---------------------------------------------------------------------------


def cloud_mode_files() -> dict[str, bool]:
    return {
        "cloud_env": CLOUD_ENV.exists(),
        "cloud_state": CLOUD_STATE.exists(),
        "cloud_profile": CLOUD_PROFILE.exists(),
    }


def intended_mode(cfg: dict | None = None) -> str:
    """Return ``local`` or ``cloud`` from on-disk artifacts."""
    files = cloud_mode_files()
    if files["cloud_env"] or files["cloud_profile"]:
        return "cloud"
    if cfg and cfg.get("cloud"):
        return "cloud"
    return "local"


def probe_runtime_creds(creds: dict) -> tuple[bool, str]:
    url, key = creds.get("url"), creds.get("api_key")
    if not url or not key:
        return False, "missing control-plane URL or runtime key"
    status, body = cloud_api("GET", url, key, "/v1/revocations/srl/signed")
    if status == 200:
        return True, "runtime key accepted by Cloud"
    if status == 404 and isinstance(body, dict):
        code = (body.get("error") or {}).get("code")
        if code == "srl_not_found":
            return True, "runtime key accepted by Cloud (no SRL yet)"
    if status == 401:
        return False, "invalid_api_key (use Quick Connect token, not ak_… id)"
    if status == 403:
        return False, "forbidden — wrong key role for this endpoint"
    return False, f"HTTP {status}: {body}"


def read_admin_key() -> str | None:
    """Tenant-admin key from env or ~/.tenuo/admin.env (never from cloud.env)."""
    key = os.environ.get("TENUO_ADMIN_KEY") or os.environ.get("TENUO_ADMIN_API_KEY")
    if not key and ADMIN_ENV.exists():
        af = read_env_file(ADMIN_ENV)
        key = af.get("TENUO_ADMIN_KEY") or af.get("TENUO_ADMIN_API_KEY")
    return key


def local_holder_pub_hex() -> str | None:
    """Hex-encoded Ed25519 public key from .state/holder_key.b64, if present."""
    if not HOLDER_KEY.exists():
        return None
    try:
        from tenuo import SigningKey
        holder = SigningKey.from_bytes(base64.b64decode(HOLDER_KEY.read_text()))
        return holder.public_key.to_bytes().hex()
    except Exception:
        return None


def _cloud_error_info(body) -> dict:
    if not isinstance(body, dict):
        return {}
    err = body.get("error")
    return err if isinstance(err, dict) else body


def trigger_fire_failure_message(status: int, body, tid: str) -> str:
    """Human-readable error when POST /v1/triggers/{id}/fire fails."""
    err = _cloud_error_info(body)
    code = err.get("code", "")
    if code == "agent_not_allowed":
        agent = load_cloud_state().get("agent_id", "?")
        return (
            f"Trigger fire failed ({status}): agent {agent} is not allowed to fire {tid}.\n"
            "This usually means setup wasn't run after a trigger rename or policy change.\n"
            "Fix: tenuo-admin setup  (needs admin key in ~/.tenuo/admin.env)"
        )
    return f"Trigger fire failed ({status}): {body}"


def probe_cloud_bindings(cfg: dict, creds: dict, *, admin_key: str | None = None) -> tuple[bool, str]:
    """Verify Cloud agent/trigger/holder bindings (dry-run fire + optional admin inspect).

    Returns (ok, detail). When ``admin_key`` is set, also compares the local holder
    key to the Cloud agent's claimed public key and checks ``allowed_triggers``.
    """
    st = load_cloud_state()
    tid = trigger_id(cfg)
    agent_id = st.get("agent_id")
    if not tid or not agent_id:
        return False, "incomplete cloud setup (missing agent_id or trigger_id)"
    url, rt_key = creds.get("url"), creds.get("api_key")
    if not url or not rt_key:
        return False, "missing runtime credentials in cloud.env"

    local_hex = local_holder_pub_hex()
    if admin_key:
        status, agent = cloud_api("GET", url, admin_key, f"/v1/agents/{agent_id}")
        if status != 200 or not isinstance(agent, dict):
            return False, f"cannot inspect agent ({status}): {agent}"
        cloud_hex = (agent.get("public_key") or "").lower()
        if local_hex and cloud_hex and cloud_hex != local_hex.lower():
            return False, (
                f"holder key mismatch (local {local_hex[:16]}… vs cloud {cloud_hex[:16]}…) "
                "— run tenuo-admin setup"
            )
        allowed = agent.get("allowed_triggers") or []
        if allowed and tid not in allowed:
            stale = ", ".join(allowed)
            return False, (
                f"agent allowed_triggers [{stale}] missing {tid} — run tenuo-admin setup"
            )

    event = {"sandbox": cfg.get("_sandbox_abs", ""), "agent_id": agent_id}
    status, body = cloud_api("POST", url, rt_key, f"/v1/triggers/{tid}/fire",
                             {"event_data": event, "dry_run": True})
    if status == 200:
        dr = (body or {}).get("dry_run", {}) if isinstance(body, dict) else {}
        if dr.get("would_issue"):
            return True, "trigger fire dry-run OK"
        return False, f"dry-run would not issue warrant: {body}"

    err = _cloud_error_info(body)
    if err.get("code") == "agent_not_allowed":
        if admin_key:
            return False, (
                f"agent {agent_id} not allowed to fire {tid} — run tenuo-admin setup"
            )
        return False, (
            f"agent not allowed to fire {tid} — run tenuo-admin setup "
            "(add admin key to ~/.tenuo/admin.env for a fuller diagnosis)"
        )
    return False, f"trigger dry-run failed ({status}): {body}"


def write_cloud_env(connect_token: str, authorizer_name: str | None = None) -> None:
    ensure_state_dir()
    cfg = load_config() if CONFIG_FILE.exists() else {}
    name = authorizer_name or cfg.get("name", "tenuo-claude")
    # Validate before writing.
    _parse_connect_token(connect_token.strip())
    # 0600: holds the runtime connect token (authorizer bearer key).
    write_secret(
        CLOUD_ENV,
        "# Written by tenuo-claude onboard — edit as needed.\n"
        f'export TENUO_CONNECT_TOKEN="{connect_token.strip()}"\n'
        f'export TENUO_AUTHORIZER_NAME="{name}"\n'
    )


def write_admin_env(admin_key: str) -> None:
    ADMIN_ENV.parent.mkdir(parents=True, exist_ok=True)
    ADMIN_ENV.write_text(f'export TENUO_ADMIN_KEY="{admin_key.strip()}"\n')
    try:
        ADMIN_ENV.chmod(0o600)
    except OSError:
        pass


def write_cloud_profile(*, url: str) -> None:
    import yaml

    data: dict = {"cloud": {"url": url.rstrip("/")}}
    CLOUD_PROFILE.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))


def write_advanced_profile(*, approver: str | None = None, approver_id: str | None = None,
                           threshold: int = 1) -> None:
    import yaml

    cloud = {}
    if approver_id:
        cloud["approver_identity_id"] = approver_id
    elif approver:
        cloud["approver_identity"] = approver
    else:
        raise SystemExit("--advanced requires --approver-id or --approver.")
    data: dict = {
        "cloud": cloud,
        "enforce": {
            "WebFetch": {
                "domains": ["docs.anthropic.com"],
                "approval": {"threshold": threshold},
            },
        },
        "mcp": {
            "enforce": {
                "delete_deployment": {
                    "approval": {
                        "threshold": threshold,
                        "exempt": {"target": "exact:staging"},
                    },
                },
            },
        },
    }
    ADVANCED_PROFILE.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))


def disable_cloud_artifacts() -> list[str]:
    """Move Cloud/advanced files aside for local mode. Returns paths moved."""
    moved = []
    for path in (CLOUD_ENV, CLOUD_STATE, CLOUD_PROFILE, ADVANCED_PROFILE):
        if path.exists():
            dest = path.with_suffix(path.suffix + ".bak")
            n = 0
            while dest.exists():
                n += 1
                dest = path.with_name(f"{path.name}.bak{n}")
            path.rename(dest)
            moved.append(f"{path.name} -> {dest.name}")
    return moved


def _docker_ok() -> tuple[bool, str]:
    return art.docker_ok()


def _native_logs(state: Path) -> None:
    log = art.native_log_path(state)
    if log.is_file():
        print(log.read_text()[-1500:])


def _start_authorizer_docker(cfg: dict, denv: dict, *, cloud: bool) -> None:
    image, name = authorizer_image(cfg), container_name(cfg)
    docker("rm", "-f", name)
    sync_authorizer_mount()
    mount = authorizer_mount_dir()
    art.assert_port_available(PORT, AUTHZ_URL, mount)
    if SRL.exists() and not cloud:
        denv["TENUO_REVOCATION_LIST"] = f"/state/{SRL.name}"
    run = ["run", "-d", "--name", name, "-p", f"127.0.0.1:{PORT}:9090",
           "-v", f"{mount.resolve()}:/state:ro"]
    for k, v in denv.items():
        run += ["-e", f"{k}={v}"]
    serve = ["serve", "--config", f"/state/{GATEWAY.name}", "--port", "9090", "--bind", "0.0.0.0"]
    print(f"Starting authorizer container {name} ({image}; pulling if needed)…")
    started = docker(*run, image, *serve)
    if started.returncode != 0:
        raise SystemExit(f"Failed to start authorizer container ({image}):\n{started.stderr.strip()}")
    art.write_runtime_meta(mount, backend="docker", image=image)

    def _on_exit() -> None:
        logs = docker("logs", name)
        raise SystemExit("Authorizer container exited during startup:\n"
                         + (logs.stdout or logs.stderr)[-1500:])

    art.wait_healthy(
        AUTHZ_URL,
        is_running=lambda: authorizer_running(cfg),
        on_exited=_on_exit,
    )
    print(f"Authorizer up (container {name}).")


def _start_authorizer_native(cfg: dict, denv: dict, *, image: str, install: bool = False) -> None:
    sync_authorizer_mount()
    mount = authorizer_mount_dir()
    binary = art.resolve_authorizer_binary(image, install=install)
    print(f"Starting native authorizer ({binary})…")
    art.start_native(
        binary=binary,
        mount=mount,
        gateway_name=GATEWAY.name,
        port=PORT,
        authz_url=AUTHZ_URL,
        denv=denv,
        srl_name=SRL.name if SRL.exists() else None,
        state=STATE,
        image=image,
    )

    def _on_exit() -> None:
        _native_logs(STATE)
        raise SystemExit("Native authorizer exited during startup (see .state/authorizer.log)")

    art.wait_healthy(
        AUTHZ_URL,
        is_running=lambda: art.native_process_alive(mount),
        on_exited=_on_exit,
    )
    print(f"Authorizer up (native, {AUTHZ_URL}).")


def _check_line(ok: bool | None, label: str, detail: str = "", hint: str = "") -> bool:
    """Print one preflight line. ``None`` = warn. Returns False if hard fail."""
    mark = "ok" if ok is True else ("!!" if ok is False else "..")
    msg = f"  {mark} {label}"
    if detail:
        msg += f" — {detail}"
    print(msg)
    if hint:
        print(f"      → {hint}")
    return ok is not False


def _find_hook_command(entries: list, subcommand: str) -> str:
    """Return the Tenuo-owned hook command from a Claude hook list."""
    for entry in entries or []:
        if not isinstance(entry, dict) or not _is_tenuo_hook(entry, subcommand):
            continue
        for inner in entry.get("hooks") or []:
            cmd = inner.get("command", "")
            if cmd:
                return cmd
    return ""


def _hook_launcher_resolves(command: str) -> tuple[bool, str]:
    """Verify the wired PreToolUse command resolves to a runnable launcher.

    Returns ``(ok, detail)``. A bare name (resolves only via the runtime PATH)
    or an absolute path that isn't executable is NOT ok — Claude would launch
    nothing, no deny JSON would be emitted, and tool calls would proceed
    ungoverned. The check is PATH-independent: a relative or bare launcher is
    treated as a failure even if it happens to be on the current PATH.
    """
    if not command:
        return False, "empty"
    try:
        parts = shlex.split(command)
    except ValueError:
        return False, "unparseable command"
    if not parts:
        return False, "empty"
    # Unwrap the POSIX fail-closed guard: `/bin/sh -c '... exec <launcher> ...'`.
    # The guarded launcher is the first token after `exec` in the script body.
    launcher = parts[0]
    if launcher in ("/bin/sh", "sh") and "-c" in parts:
        body = parts[parts.index("-c") + 1] if parts.index("-c") + 1 < len(parts) else ""
        try:
            tokens = shlex.split(body)
        except ValueError:
            tokens = []
        if "exec" in tokens and tokens.index("exec") + 1 < len(tokens):
            launcher = tokens[tokens.index("exec") + 1]
        else:
            return False, "guard missing exec target"
    p = Path(launcher)
    if not p.is_absolute():
        return False, f"PATH-dependent: {launcher!r} (re-wire with `refresh`)"
    if not (p.is_file() and os.access(p, os.X_OK)):
        return False, f"not executable: {launcher}"
    return True, f"resolves: {launcher}"


def _check_wiring(cfg: dict | None, ok: bool) -> bool:
    """Validate launcher + generated Claude/MCP wiring."""
    if LAUNCHER.is_file():
        exe = os.access(LAUNCHER, os.X_OK)
        ok = _check_line(exe, "launcher", LAUNCHER_REL,
                         "" if exe else f"run: chmod +x {LAUNCHER_REL}") and ok
        if exe:
            try:
                r = subprocess.run(
                    [str(LAUNCHER), "status"], cwd=DEMO_DIR, capture_output=True,
                    text=True, timeout=45)
                smoke_ok = r.returncode == 0
                ok = _check_line(
                    smoke_ok, "launcher smoke", "status ok" if smoke_ok else "status failed",
                    "" if smoke_ok else "run: uv sync && tenuo-claude refresh") and ok
            except subprocess.TimeoutExpired:
                ok = _check_line(False, "launcher smoke", "timed out",
                                 "check authorizer / docker") and ok
    else:
        _check_line(None, "launcher", "not present", "optional — PyPI installs use `tenuo-claude` on PATH")

    if not cfg:
        return ok

    hooks = DEMO_DIR / ".claude" / "settings.json"
    if hooks.exists():
        try:
            settings = json.loads(hooks.read_text())
            pre = (settings.get("hooks") or {}).get("PreToolUse") or []
            cmd = _find_hook_command(pre, "_hook")
            expect = hook_wiring_command_string("_hook")
            drift = cmd != expect
            ok = _check_line(
                not drift, "hook wiring",
                "current" if not drift else f"stale (want {expect!r})",
                "" if not drift else "tenuo-claude refresh") and ok
            # The deny JSON is only emitted when the hook actually runs; if the
            # wired command can't resolve to an executable, Claude launches
            # nothing, no deny is produced, and tool calls proceed ungoverned.
            # Verify resolvability INDEPENDENT of the wiring we just compared.
            launcher_ok, launcher_detail = _hook_launcher_resolves(cmd)
            ok = _check_line(
                launcher_ok, "hook launcher",
                launcher_detail,
                "" if launcher_ok else "tenuo-claude refresh "
                "(re-wires an absolute, PATH-independent launcher)") and ok
        except (json.JSONDecodeError, IndexError, KeyError):
            ok = _check_line(False, "hook wiring", "unreadable settings.json",
                             "tenuo-claude refresh") and ok
    else:
        _check_line(None, "claude hooks", "not wired yet", "run: tenuo-claude init")

    expected_mcp = mcp_wiring(cfg)
    mcp_path = DEMO_DIR / ".mcp.json"
    if expected_mcp:
        if mcp_path.exists():
            try:
                actual = json.loads(mcp_path.read_text())
                drift = actual != expected_mcp
                ok = _check_line(
                    not drift, "mcp wiring",
                    "current" if not drift else "stale",
                    "" if not drift else "tenuo-claude refresh") and ok
            except json.JSONDecodeError:
                ok = _check_line(False, "mcp wiring", "invalid JSON",
                                 "tenuo-claude refresh") and ok
        else:
            _check_line(None, "mcp wiring", "missing", "tenuo-claude init")
    elif mcp_path.exists():
        _check_line(None, "mcp wiring", "present but mcp.downstream unset",
                    "remove .mcp.json or restore mcp: in tenuo.yaml")
    return ok


def cmd_check(_args) -> None:
    """Preflight before init/up: deps, credentials, mode, suggested next steps."""
    ok = True
    cloud_bindings_ok = True
    print("Preflight check\n")

    # Fail fast on the most security-relevant misconfiguration: a tenant-admin key
    # exported into the runtime env. The admin key can mint/modify triggers; it must
    # live only in ~/.tenuo/admin.env, never where the authorizer/hook can read it.
    reach = runtime_env()
    admin_leak = next((v for v in ADMIN_KEY_VARS if reach.get(v)), None)
    if admin_leak:
        ok = _check_line(False, "runtime env", f"{admin_leak} is exported",
                         "unset it; admin key belongs in ~/.tenuo/admin.env only") and ok
    else:
        _check_line(True, "runtime env", "no admin key leaked")

    py_ok = sys.version_info >= (3, 10)
    ok = _check_line(py_ok, "python", f"{sys.version_info.major}.{sys.version_info.minor}") and ok

    try:
        import tenuo  # noqa: F401
        import yaml  # noqa: F401
        ok = _check_line(True, "python deps", "tenuo, PyYAML installed") and ok
    except ImportError as exc:
        ok = _check_line(False, "python deps", str(exc),
                         "run: uv sync  (or pip install -r requirements.txt)") and ok

    d_ok, d_msg = _docker_ok()
    if d_ok:
        _check_line(True, "docker", d_msg)
    else:
        _check_line(None, "docker", d_msg, "optional — `tenuo-claude up --native` uses a host binary")
    native_bin = art.find_authorizer_binary(DEFAULT_AUTHZ_IMAGE)
    pinned_ver = art.authorizer_crate_version(DEFAULT_AUTHZ_IMAGE)
    if native_bin:
        _check_line(True, "authorizer binary", str(native_bin))
        installed = art.query_binary_version(native_bin)
        if installed and art.version_compatible(installed, pinned_ver):
            _check_line(True, "authorizer version", art.crate_version_from_authorizer_version(installed))
        elif installed:
            _check_line(
                None, "authorizer version",
                f"{art.crate_version_from_authorizer_version(installed)} (want {pinned_ver})",
                art.install_hint(DEFAULT_AUTHZ_IMAGE),
            )
    elif not d_ok:
        _check_line(
            False, "authorizer binary", "not installed",
            art.install_hint(DEFAULT_AUTHZ_IMAGE),
        )
        ok = False

    claude = shutil.which("claude")
    _check_line(bool(claude), "claude CLI", claude or "not on PATH",
                "install Claude Code; optional for check / verify --deep")

    ok = _check_line(CONFIG_FILE.exists(), "tenuo.yaml", str(CONFIG_FILE)) and ok

    cfg = None
    if CONFIG_FILE.exists():
        try:
            cfg = load_config()
        except SystemExit as exc:
            ok = _check_line(False, "policy load", str(exc)) and ok

    ok = _check_wiring(cfg, ok)

    if STATE.exists():
        perm_ok, perm_issues = check_state_permissions()
        ok = _check_line(
            perm_ok, "secret permissions",
            "ok" if perm_ok else "; ".join(perm_issues),
            "" if perm_ok else "run: tenuo-claude refresh") and ok

    sink_fail = receipt_sink_failure()
    if sink_fail:
        ok = _check_line(False, "audit sink", f"receipts unwritable — {sink_fail}",
                         f"fix {RECEIPTS.parent} permissions/disk space") and ok

    mode = intended_mode(cfg)
    files = cloud_mode_files()
    _check_line(True, "mode", mode, None)
    if managed_mode(cfg):
        tid = trigger_id(cfg) or "?"
        _check_line(True, "enterprise", "managed Cloud (local policy = overlay only)", None)
        _check_line(True, "authority", f"Cloud trigger {tid}", None)
        _check_line(True, "trust", "cloud root only", None)
        if mode != "cloud" and not files["cloud_env"]:
            ok = _check_line(
                False, "managed", "cloud.managed set but no Cloud runtime configured",
                "run `tenuo-admin setup` (managed mode requires a Cloud trigger)") and ok
        widened = local_widened_tools(cfg, warrant_capabilities())
        if widened:
            _check_line(None, "attenuation",
                        f"local widens Cloud warrant: {', '.join(widened)} (ignored)",
                        "tenuo-admin setup")
        else:
            _check_line(True, "attenuation",
                        "no extra local tools; constraint-level attenuation not verified", None)
    _check_line(True, "posture",
                "dry-run (observe-only)" if is_audit_mode(cfg) else "enforce", None)
    for note in posture_warnings(cfg):
        _check_line(None, "policy", note, "edit tenuo.yaml")
    if mode == "local" and any(files.values()):
        _check_line(None, "cloud files", "present but mode is local",
                    "remove/rename .state/cloud.env or run: tenuo-claude init --local")

    if mode == "cloud" or files["cloud_env"]:
        if not files["cloud_env"]:
            ok = _check_line(False, "cloud.env", "missing",
                             "run: tenuo-claude onboard --cloud") and ok
        else:
            creds = cloud_creds(cfg or {})
            parsed = bool(creds.get("url") and creds.get("api_key"))
            ok = _check_line(parsed, "connect credentials", "parsed from cloud.env") and ok
            if parsed:
                p_ok, p_msg = probe_runtime_creds(creds)
                ok = _check_line(p_ok, "cloud probe", p_msg) and ok
        if ADMIN_ENV.exists():
            _check_line(True, "admin.env", str(ADMIN_ENV))
        else:
            _check_line(None, "admin.env", "missing",
                        "needed once for tenuo-admin setup (Settings → API Keys)")
        if files["cloud_state"]:
            st = load_cloud_state()
            tid = st.get("trigger_id")
            _check_line(bool(tid), "cloud setup", f"trigger {tid}" if tid else "incomplete")
            if parsed and st.get("agent_id") and tid:
                admin_key = read_admin_key()
                cloud_bindings_ok, b_msg = probe_cloud_bindings(
                    cfg or {}, creds, admin_key=admin_key)
                ok = _check_line(
                    cloud_bindings_ok, "cloud bindings", b_msg,
                    "" if cloud_bindings_ok else "run: tenuo-admin setup") and ok
        else:
            _check_line(None, "cloud setup", "not run yet", "run: tenuo-admin setup")
        if cfg and has_approval_gates(cfg) and not approval_policy_id(cfg):
            _check_line(None, "approval", "policy not wired", "re-run: tenuo-admin setup")

    run_cfg = cfg or {"name": "tenuo-claude"}
    if WARRANT.exists():
        exp = warrant_expired()
        soon, exp_at = warrant_expires_within(24)
        detail = "present"
        if exp:
            detail += " (expired — run up)"
        elif soon:
            detail += f" (expires soon: {exp_at} — run up to refresh)"
        _check_line(None if exp or soon else True, "warrant", detail)
    elif mode == "local":
        _check_line(None, "warrant", "missing", "run: tenuo-claude init")

    # A managed authorizer is a systemd/launchd service reachable only via the Unix
    # socket — invisible to the Docker-name runtime check. When the endpoint is Unix,
    # trust a socket answer for liveness and use runtime metadata as detail only.
    endpoint_mode, endpoint_loc = authz_endpoint()
    st = _status_json()
    running = bool(st) if endpoint_mode == "unix" else authorizer_running(run_cfg)
    if running:
        mount = authorizer_mount_dir()
        meta = art.read_runtime_meta(mount)
        backend = meta.get("backend") or "unknown"
        running_ver = (st or {}).get("version")
        ver_detail = f"up ({authz_display()}) | {backend}"
        if running_ver:
            ver_detail += f" | v{running_ver}"
            if running_ver != pinned_ver:
                _check_line(
                    None, "running authorizer",
                    ver_detail,
                    f"want v{pinned_ver} — restart after upgrade",
                )
            else:
                _check_line(True, "running authorizer", ver_detail)
        else:
            _check_line(True, "running authorizer", ver_detail)
    elif endpoint_mode == "unix":
        _check_line(None, "authorizer", f"down (unix {endpoint_loc})",
                    "managed: restart the systemd/launchd service & check socket ownership")
    else:
        img = authorizer_image(run_cfg)
        img_ver = art.authorizer_crate_version(img)
        if img_ver != pinned_ver:
            _check_line(None, "authorizer image", img_ver, f"pinned package expects {pinned_ver}")
        _check_line(None, "authorizer", "down", "run: tenuo-claude up")

    print("\nSuggested next steps:")
    hooks_wired = (DEMO_DIR / ".claude" / "settings.json").exists()
    if mode == "cloud" and files.get("cloud_state") and not cloud_bindings_ok:
        print("  tenuo-admin setup && tenuo-claude up")
    elif not hooks_wired:
        print("  tenuo-claude init")
    elif mode == "cloud" and not files["cloud_state"]:
        print("  tenuo-admin setup && tenuo-claude up")
    elif not running:
        # Reuse the transport-aware liveness from above: a managed Unix socket is
        # served by a SYSTEM service, not `tenuo-claude up`.
        if endpoint_mode == "unix":
            print("  # managed: (re)install/restart the systemd/launchd authorizer service,")
            print("  #          then check the socket is root-owned")
        else:
            print("  tenuo-claude up")
    elif WARRANT.exists() and not warrant_expired():
        print("  tenuo-claude verify")
        print("  open Claude Code in this directory")
    else:
        print("  tenuo-claude up   # refresh warrant (authorizer already running)")
    print("\nCHECK OK" if ok else "\nCHECK FAILED — fix items marked !!")
    raise SystemExit(0 if ok else 1)


def _prompt(text: str, default: str = "") -> str:
    try:
        suffix = f" [{default}]" if default else ""
        line = input(f"{text}{suffix}: ").strip()
    except EOFError:
        line = ""
    return line or default


def cmd_onboard(args) -> None:
    """Interactive wizard for local or Cloud onboarding."""
    cloud = getattr(args, "cloud", False)
    local = getattr(args, "local", False)
    if not cloud and not local:
        choice = _prompt("Mode — (l)ocal or (c)loud", "local").lower()
        cloud = choice.startswith("c")
        local = not cloud

    token = None
    cloud_url = None
    approver = None
    approver_id = None
    admin_key = None
    if cloud:
        token = getattr(args, "connect_token", None) or os.environ.get("TENUO_CONNECT_TOKEN")
        if not token and CLOUD_ENV.exists():
            token = runtime_env().get("TENUO_CONNECT_TOKEN")
        if not token and not getattr(args, "yes", False):
            token = _prompt("Paste Quick Connect token (tenuo_ct_…)")
        if not token:
            raise SystemExit("Cloud onboarding needs TENUO_CONNECT_TOKEN (Quick Connect → Authorizer Only).")
        cloud_url = _parse_connect_token(token.strip())["url"]

        if getattr(args, "advanced", False) or getattr(args, "demo", False):
            approver = getattr(args, "approver", None)
            approver_id = getattr(args, "approver_id", None)
            if not approver and not approver_id and not getattr(args, "yes", False):
                approver = _prompt("Approver display name (must exist in Cloud)")
            if not approver and not approver_id:
                raise SystemExit("--advanced requires --approver-id or --approver.")

        admin_key = getattr(args, "admin_key", None) or os.environ.get("TENUO_ADMIN_KEY")
        if not admin_key and ADMIN_ENV.exists():
            admin_key = read_env_file(ADMIN_ENV).get("TENUO_ADMIN_KEY")
        if not admin_key and not getattr(args, "yes", False):
            admin_key = _prompt("Paste tenant-admin key for one-time setup (blank = skip)", "")

    # Handle --pack flag
    pack_name = getattr(args, "pack", None)
    if pack_name:
        # Render policy pack instead of scaffold example
        try:
            from tenuo_claude_code.packs import render_policy_pack
            render_policy_pack(argparse.Namespace(pack=pack_name))
            created = True
        except Exception as e:
            raise SystemExit(f"Policy pack '{pack_name}' failed: {e}")
    else:
        created = scaffold_example_policy(DEMO_DIR, no_scaffold=getattr(args, "no_scaffold", False))
    _ensure_state_in_gitignore()

    if cloud:
        write_cloud_env(token)

        write_cloud_profile(url=cloud_url)
        print(f"Wrote {CLOUD_PROFILE.name}")

        if getattr(args, "advanced", False) or getattr(args, "demo", False):
            write_advanced_profile(approver=approver, approver_id=approver_id)
            print(f"Wrote {ADVANCED_PROFILE.name} (advanced — re-run `tenuo-admin setup`)")

        if admin_key:
            write_admin_env(admin_key)
            print(f"Wrote {ADMIN_ENV}")

    if not created and not getattr(args, "skip_preflight", False):
        print("\nRunning preflight…")
        try:
            cmd_check(argparse.Namespace())
        except SystemExit as exc:
            if exc.code not in (0, None):
                if getattr(args, "yes", False):
                    print("Preflight failed — continuing (--yes).")
                elif not _prompt("Preflight failed — continue anyway?", "n").lower().startswith("y"):
                    raise SystemExit(1)

    if local or not cloud:
        moved = disable_cloud_artifacts()
        if moved:
            print("Moved aside for local mode:", ", ".join(moved))
        cmd_init(argparse.Namespace(cloud=False, local=True))
        cmd_up(argparse.Namespace())
        try:
            cmd_verify(argparse.Namespace(deep=False, no_live=True))
        except SystemExit as exc:
            raise SystemExit(1 if exc.code is None else exc.code)
        print("\nOnboard complete (local). Open Claude Code in this directory.")
        return

    cmd_init(argparse.Namespace(cloud=False, local=False))

    if admin_key:
        env = os.environ.copy()
        for var in ADMIN_KEY_VARS:
            env.pop(var, None)
        r = subprocess.run(
            [sys.executable, "-m", "tenuo_claude_code.admin", "setup"],
            cwd=DEMO_DIR, env=env,
        )
        if r.returncode != 0:
            raise SystemExit("tenuo-admin setup failed — fix errors above and re-run setup")
    else:
        print("\nSkipped tenuo-admin setup (no admin key). Run setup with a tenant-admin key.")

    for var in ADMIN_KEY_VARS:
        os.environ.pop(var, None)
    cmd_up(argparse.Namespace())
    try:
        cmd_verify(argparse.Namespace(deep=False, no_live=True))
    except SystemExit as exc:
        raise SystemExit(1 if exc.code is None else exc.code)
    print("\nOnboard complete (cloud). Open Claude Code in this directory.")


def cmd_bootstrap(args) -> None:
    """check → init → up → verify (--local default)."""
    # Handle --native flag by setting environment variable
    if getattr(args, "native", False):
        os.environ["TENUO_AUTHORIZER_BACKEND"] = "native"

    # Handle --install flag
    if getattr(args, "install", False):
        cmd_install_authorizer(argparse.Namespace())

    local = getattr(args, "local", True) and not getattr(args, "cloud", False)
    ns = dict(local=True, cloud=False, yes=True,
              no_scaffold=getattr(args, "no_scaffold", False),
              pack=getattr(args, "pack", None),
              skip_preflight=True)
    if local:
        cmd_onboard(argparse.Namespace(**ns))
    else:
        cmd_onboard(argparse.Namespace(
            local=False, cloud=True, yes=getattr(args, "yes", False),
            no_scaffold=getattr(args, "no_scaffold", False),
            pack=getattr(args, "pack", None),
            advanced=getattr(args, "advanced", False) or getattr(args, "demo", False),
            connect_token=getattr(args, "connect_token", None),
            approver=getattr(args, "approver", None),
            approver_id=getattr(args, "approver_id", None),
            admin_key=getattr(args, "admin_key", None),
            skip_preflight=True,
        ))


def load_cloud_state() -> dict:
    try:
        if CLOUD_STATE.exists():
            return json.loads(CLOUD_STATE.read_text())
    except Exception:
        return {}
    return {}


def save_cloud_state(patch: dict) -> None:
    st = load_cloud_state()
    st.update(patch)
    CLOUD_STATE.write_text(json.dumps(st, indent=2))


def trigger_id(cfg: dict) -> str | None:
    """Trigger id to fire on `up`: tenuo.yaml cloud.trigger, else cloud-setup state."""
    return (cfg.get("cloud") or {}).get("trigger") or load_cloud_state().get("trigger_id")


def use_cloud_trigger(cfg: dict) -> bool:
    """True only when a Cloud trigger can actually issue a warrant right now: creds
    (URL + API key) AND a configured trigger.

    A `trigger_id()` alone is NOT sufficient — it can linger in a stale
    `.state/cloud_state.json` after the creds/profile are gone, leaving the project
    effectively local. Anything that relaxes constraints "because the Cloud trigger
    carries the gate" must key off this, not `trigger_id()`: otherwise an
    approval-gated tool relaxes to a wildcard and then gets minted LOCALLY with no
    approval gate (fail-open). The decision to fire a trigger uses the same predicate.
    """
    if not trigger_id(cfg):
        return False
    creds = cloud_creds(cfg)
    return bool(creds.get("url") and creds.get("api_key"))


def fire_session_warrant(cfg: dict, creds: dict) -> tuple[str, str]:
    """Fire the configured trigger -> (warrant_b64, tenant_root_hex). Runtime key."""
    tid = trigger_id(cfg)
    if not tid:
        raise SystemExit("No trigger configured. Run `tenuo-admin setup` first.")
    agent = load_cloud_state().get("agent_id", "")
    event = {"sandbox": cfg["_sandbox_abs"], "agent_id": agent}
    status, body = cloud_api("POST", creds["url"], creds["api_key"],
                             f"/v1/triggers/{tid}/fire", {"event_data": event})
    if status != 200 or not isinstance(body, dict) or not body.get("warrant"):
        raise SystemExit(trigger_fire_failure_message(status, body, tid))
    # Resolve the trust anchor INDEPENDENTLY of the warrant: a pinned root
    # (TENUO_TENANT_ROOT) or the authenticated Cloud /tenant lookup. Deriving the
    # root from the warrant's own issuer would mean "trust whoever signed this",
    # so it is allowed only in unmanaged Cloud mode (already a weaker trust model)
    # and never in managed mode, where cloud-root-only is the whole point.
    root = creds.get("root") or fetch_tenant_root(creds["url"], creds["api_key"])
    if not root and not managed_mode(cfg):
        root = root_from_warrant_issuer(body["warrant"])
    if not root:
        msg = "Fired warrant but could not resolve tenant root for trust anchor."
        if managed_mode(cfg):
            msg += ("\n  Managed mode pins trust to the tenant root (TENUO_TENANT_ROOT or the\n"
                    "  authenticated Cloud /tenant lookup) and will NOT derive trust from the\n"
                    "  warrant itself. Re-run `tenuo-admin setup` to record the tenant root.")
        raise SystemExit(msg)
    return body["warrant"], root


def authorizer_image(cfg: dict) -> str:
    return (os.environ.get("TENUO_AUTHORIZER_IMAGE")
            or (cfg.get("authorizer") or {}).get("image") or DEFAULT_AUTHZ_IMAGE)


def container_name(cfg: dict) -> str:
    return f"tenuo-authorizer-{slug(cfg.get('name', 'tenuo-claude'))}"


def docker(*args: str) -> subprocess.CompletedProcess:
    """Run a docker subcommand, captured. Fail closed with a clear message if
    Docker isn't installed (the authorizer ships only as a container image)."""
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True)
    except FileNotFoundError:
        raise SystemExit("Docker not found. Install Docker Desktop / engine — the "
                         "Tenuo authorizer runs as a container (tenuo/authorizer).")


def authorizer_running(cfg: dict) -> bool:
    mount = authorizer_mount_dir()
    backend = art.read_runtime_backend(mount)
    if backend == "native" or art.native_pid_path(mount).is_file():
        return art.native_running(mount, resolve_authz_url())
    # No native state recorded, so any authorizer we manage would be the Docker
    # container. On a host without Docker (e.g. macOS/WSL on the native backend)
    # nothing we manage is running — report that instead of hard-failing.
    if shutil.which("docker") is None:
        return False
    r = docker("inspect", "-f", "{{.State.Running}}", container_name(cfg))
    return r.returncode == 0 and r.stdout.strip() == "true"


def warrant_expired() -> bool:
    try:
        from tenuo import Warrant
        return Warrant.from_base64(WARRANT.read_text()).is_expired()
    except Exception:
        return False  # missing/unreadable warrant still fails closed at the authorizer


def warrant_expires_within(hours: float = 24) -> tuple[bool, str]:
    """True when the session warrant expires within ``hours`` (and is not already expired)."""
    try:
        from tenuo import Warrant
        w = Warrant.from_base64(WARRANT.read_text())
        if w.is_expired():
            return False, ""
        exp_raw = w.expires_at()
        exp = datetime.fromisoformat(exp_raw.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        remaining = (exp - datetime.now(timezone.utc)).total_seconds()
        if 0 < remaining <= hours * 3600:
            return True, exp_raw
    except Exception:
        pass
    return False, ""


def _authorizer_status_line(cfg: dict) -> str:
    mount = authorizer_mount_dir()
    meta = art.read_runtime_meta(mount)
    backend = meta.get("backend")
    if backend == "native":
        binary = meta.get("binary")
        return f"native ({binary})" if binary else "native"
    if backend == "docker":
        image = meta.get("image") or authorizer_image(cfg)
        return f"docker ({image})"
    try:
        if docker("inspect", "-f", "{{.State.Running}}", container_name(cfg)).stdout.strip() == "true":
            return f"docker ({authorizer_image(cfg)})"
    except SystemExit:
        pass
    if art.native_pid_path(mount).is_file():
        return "native"
    return "unknown backend"


def _record_fired_warrant(warrant_b64: str) -> None:
    write_secret(WARRANT, warrant_b64)
    try:
        from tenuo import Warrant
        update_state_warrant_id(Warrant.from_base64(warrant_b64).id)
    except Exception:
        pass


def cmd_install_authorizer(args) -> None:
    """Install the pinned ``tenuo-authorizer`` binary to ``~/.tenuo/bin``."""
    image = DEFAULT_AUTHZ_IMAGE
    try:
        bind_project_paths(sys.modules[__name__])
        try:
            image = authorizer_image(load_config())
        except SystemExit:
            pass
    except SystemExit:
        pass
    path = art.install_authorizer(image, force=getattr(args, "force", False))
    installed = art.query_binary_version(path)
    print(f"Installed: {path}")
    if installed:
        print(f"Version:   {installed}")
    print("Next: `tenuo-claude up --native`")


def _assert_managed_runtime(cfg: dict, use_trigger: bool) -> None:
    """In managed Cloud mode, authority MUST come from the Cloud trigger (a
    root-signed warrant). Refuse to fall back to a local issuer / local mint and
    fail closed, so a missing trigger or unreachable Cloud can never silently
    downgrade a managed endpoint to self-signed local authority."""
    if managed_mode(cfg) and not use_trigger:
        raise SystemExit(
            "Managed Cloud mode is enabled but no Cloud trigger is configured/reachable.\n"
            "  Refusing to issue or trust a local warrant (fail-closed): in managed mode all\n"
            "  authority must chain to the Cloud root. Fix: ensure the runtime token + trigger\n"
            "  are present (`tenuo-admin setup`), or remove `cloud.managed` for local use.")


def _attenuation_notice(cfg: dict) -> list[str]:
    """Operator-facing lines about local→Cloud attenuation (managed mode).

    Reads the active session warrant and reports any tools the local policy
    governs that the Cloud warrant does not grant (widening, which is ignored).
    """
    widened = local_widened_tools(cfg, warrant_capabilities())
    if not widened:
        return []
    return [
        f"!! local policy widens the Cloud warrant: {', '.join(widened)}",
        "   ignored in managed mode (not granted by Cloud — these calls are denied).",
        "   to govern these tools, update the Cloud trigger: tenuo-admin setup",
    ]


def cmd_up(_args) -> None:
    cfg = load_config()
    creds = cloud_creds(cfg)
    use_trigger = use_cloud_trigger(cfg)
    _assert_managed_runtime(cfg, use_trigger)

    if not WARRANT.exists() and not use_trigger:
        raise SystemExit("Run `tenuo-claude init` first.")
    refreshed = False
    if warrant_expired() or (use_trigger and not WARRANT.exists()):
        # Re-apply tenuo.yaml (reuse issuer locally; re-fire trigger on Cloud).
        # Trust anchor unchanged — no container restart strictly required for the
        # warrant itself (it rides in every request header).
        print("Warrant expired — refreshing from tenuo.yaml…")
        if use_trigger or (ISSUER_KEY.exists() and HOLDER_KEY.exists() and WARRANT.exists()):
            refresh_policy(cfg)
        else:
            generate(cfg)
        refreshed = True
    if authorizer_running(cfg):
        if refreshed:
            refresh_subwarrants(cfg)
            print("Session warrant refreshed (running authorizer untouched).")
        else:
            print("Authorizer already running.")
        return cmd_status(_args)

    # Only authorizer-scoped values are passed to the container (explicit -e),
    # never the host environment or any admin key (separation of duties).
    cloud_url, api_key = creds["url"], creds["api_key"]
    cloud = use_trigger or bool(cloud_url and api_key)
    denv: dict = {}
    if api_key:
        denv["TENUO_API_KEY"] = api_key
    if cloud:
        denv["TENUO_CONTROL_PLANE_URL"] = cloud_url
        denv["TENUO_AUTHORIZER_NAME"] = cfg.get("name", "tenuo-claude")

    if use_trigger:
        # Cloud-issued session warrant: fire the trigger, trust the tenant ROOT
        # ONLY (no local issuer — all authority chains to the cloud root).
        warrant_b64, root = fire_session_warrant(cfg, creds)
        _record_fired_warrant(warrant_b64)
        denv["TENUO_TRUSTED_KEYS"] = root
        managed = managed_mode(cfg)
        tag = "Managed Cloud mode" if managed else "Cloud mode"
        print(f"{tag} (trigger {trigger_id(cfg)}): root-signed session warrant, "
              f"trust anchor {root[:16]}… (cloud root only)")
        if managed:
            for line in _attenuation_notice(cfg):
                print(f"  {line}")
    elif cloud:
        # Locally-minted warrant: trust the tenant root AND the local issuer.
        root = creds["root"] or fetch_tenant_root(cloud_url, api_key)
        if not root:
            raise SystemExit("Cloud configured but could not resolve tenant root key.")
        denv["TENUO_TRUSTED_KEYS"] = f"{root},{ISSUER_PUB.read_text().strip()}"
        print(f"Cloud mode: {cloud_url} (tenant root {root[:16]}…)")
    else:
        denv["TENUO_TRUSTED_KEYS"] = ISSUER_PUB.read_text().strip()
        print("Local mode (no Cloud).")

    # Refresh the gateway from tenuo.yaml (routes only, no keys) so it's aligned
    # even for a Cloud-issued warrant — in particular the spawn_agent route.
    write_gateway(cfg, enforced_capabilities(cfg))
    # Derive per-subagent child warrants from the now-final session warrant.
    refresh_subwarrants(cfg)
    roles = subagent_roles(cfg)
    if roles:
        print(f"Subagent warrants: {', '.join(roles)} (attenuated from the session).")

    # Launch the authorizer (Docker container or native binary).
    image = authorizer_image(cfg)
    backend = art.choose_backend(_args)
    if backend == "native":
        _start_authorizer_native(cfg, denv, image=image, install=getattr(_args, "install", False))
    else:
        _start_authorizer_docker(cfg, denv, cloud=cloud)
    cmd_status(_args)


def _stop_authorizer(cfg: dict) -> bool:
    """Stop the authorizer (native process or Docker container). Returns whether
    anything was actually running. Shared by `down`, `disable`, and `uninstall`."""
    mount = authorizer_mount_dir()
    stopped = False
    if art.read_runtime_backend(mount) == "native" or art.native_pid_path(mount).is_file():
        stopped = art.stop_native(mount)
    if _docker_ok()[0]:
        name = container_name(cfg)
        if docker("inspect", "-f", "{{.State.Running}}", name).returncode == 0:
            docker("rm", "-f", name)
            art.clear_runtime_meta(mount)
            stopped = True
    return stopped


def cmd_down(_args) -> None:
    cfg = load_config()
    print("Stopped authorizer." if _stop_authorizer(cfg) else "Authorizer not running.")


def _teardown_cfg() -> dict:
    """Minimal config for teardown that works even when `tenuo.yaml` is missing or
    broken. `disable`/`uninstall` must be able to clean up a half-removed project,
    so we fall back to the project name recorded in `.state/state.json` (used only
    to name the Docker container) rather than failing on `load_config`."""
    try:
        return load_config()
    except SystemExit:
        name = "tenuo-claude"
        try:
            if STATE_JSON.is_file():
                name = json.loads(STATE_JSON.read_text()).get("name", name) or name
        except (OSError, json.JSONDecodeError, ValueError):
            pass
        return {"name": name}


def cmd_disable(_args) -> None:
    """Turn governance off without deleting anything: remove Tenuo's hook wiring
    so Claude Code / Cursor stop calling the authorizer, then stop it. Policy,
    warrant, and keys are left in place — re-enable any time with `up` (or
    re-wire with `init`). Works even if `tenuo.yaml` is missing or broken."""
    cfg = _teardown_cfg()
    changes = remove_claude_wiring()
    stopped = _stop_authorizer(cfg)
    if changes:
        for line in changes:
            print(f"  {line}")
    else:
        print("  no Tenuo wiring found (nothing to unwire)")
    print("Stopped authorizer." if stopped else "Authorizer was not running.")
    if managed_mode(cfg):
        print("Note: this only removes LOCAL wiring. Organization-managed enforcement "
              "(MDM/managed settings) may still be active, and the next managed hook "
              "will fail closed until `tenuo-claude up` restores a Cloud warrant.")
    print("Governance disabled. Re-enable with `tenuo-claude up`, "
          "or remove everything with `tenuo-claude uninstall`.")


def cmd_uninstall(args) -> None:
    """Full teardown: unwire hooks, stop the authorizer, and (unless --keep-state)
    delete the local `.state` directory (warrant, signing keys, gateway, receipts,
    and any Cloud credentials). `tenuo.yaml` is never touched. Works even if
    `tenuo.yaml` is missing or broken, so a half-removed project can be cleaned up."""
    cfg = _teardown_cfg()
    keep_state = getattr(args, "keep_state", False)
    targets = [] if keep_state else [p for p in (STATE,) if p.exists()]
    if not getattr(args, "yes", False):
        print("This will:")
        print("  • remove Tenuo hooks from .claude/settings.json and .mcp.json")
        print("  • stop the authorizer")
        if targets:
            print(f"  • DELETE {STATE} (warrant, signing keys, gateway, receipts, "
                  "Cloud credentials)")
        print("  tenuo.yaml is left untouched.")
        try:
            reply = input("Proceed? [y/N] ").strip().lower()
        except EOFError:
            reply = ""
        if reply not in ("y", "yes"):
            print("Aborted.")
            return
    changes = remove_claude_wiring()
    stopped = _stop_authorizer(cfg)
    for line in changes:
        print(f"  {line}")
    if stopped:
        print("  stopped authorizer")
    if keep_state:
        print("  kept .state (--keep-state)")
    else:
        import shutil as _shutil
        for path in targets:
            _shutil.rmtree(path, ignore_errors=True)
            print(f"  deleted {path}")
    if managed_mode(cfg):
        print("Note: organization-managed enforcement (MDM/managed settings) is not "
              "removed by this command and may still be active; with local state gone, "
              "the next managed hook fails closed until you re-enroll (`up`).")
    print("Uninstalled. Re-install with `tenuo-claude init` (or `bootstrap`).")


def _status_json():
    mode, loc = authz_endpoint()
    try:
        if mode == "unix":
            if os.name != "posix":
                return None
            # Reachability probe (diagnostic, not an enforcement decision): match the
            # strictness of the active context so it doesn't false-pass/-fail.
            ok, _ = _safe_managed_socket(loc, managed=_managed_enforce_pinned())
            if not ok:
                return None
            status, raw = _UDSConnection(loc, timeout=3).request("GET", "/status")
            return json.loads(raw.decode()) if status == 200 else None
        with urllib.request.urlopen(loc + "/status", timeout=3) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def cmd_status(_args) -> None:
    cfg = load_config()
    st = json.loads(STATE_JSON.read_text()) if STATE_JSON.exists() else {}
    print(f"policy      : {CONFIG_FILE.name}  (sandbox {cfg['_sandbox_abs']})")
    print(f"warrant     : {st.get('warrant_id', '<none — run init>')}")
    if WARRANT.exists():
        try:
            from tenuo import Warrant
            w = Warrant.from_base64(WARRANT.read_text())
            flag = ("  !! EXPIRED — run `tenuo-claude up` to refresh"
                    if w.is_expired() else "")
            soon, _ = warrant_expires_within(24)
            if soon and not flag:
                flag = "  !! expires within 24h — run `tenuo-claude up` to refresh"
            print(f"  expires   : {w.expires_at()}{flag}")
        except Exception:
            print("  expires   : <unreadable warrant>")
    if managed_mode(cfg):
        tid = trigger_id(cfg) or "?"
        print("enterprise  : managed Cloud — local policy is overlay/attenuation only")
        print(f"authority   : Cloud trigger {tid} (capability changes require `tenuo-admin setup`)")
        print("trust       : cloud root only (local issuer not trusted)")
        print("posture     : enforce (pinned by org)")
        widened = local_widened_tools(cfg, warrant_capabilities())
        if widened:
            print(f"drift       : !! local policy widens Cloud warrant ({', '.join(widened)}); ignored")
            print("fix         : add these tools to the Cloud trigger (tenuo-admin setup)")
    gov = ", ".join(cfg["enforce"].keys())
    aud = ", ".join(cfg.get("audit", []) or [])
    if is_audit_mode(cfg):
        print("mode        : DRY-RUN — observe-only (decisions logged, NOT enforced)")
    for w in posture_warnings(cfg):
        print(f"posture     : !! {w}")
    print(f"enforced    : {gov or '<none>'}")
    print(f"allow       : {aud or '<none>'}   | default: {default_mode(cfg)}")
    if has_approval_gates(cfg):
        cs = load_cloud_state()
        cloud_cfg = cfg.get("cloud") or {}
        who = (cs.get("web_fetch_approver") or cloud_cfg.get("approver_identity")
               or cloud_cfg.get("approver_identity_id") or "?")
        pid = approval_policy_id(cfg)
        wired = f"policy {pid}" if pid else "NOT set up (run `tenuo-admin setup`)"
        gates = cs.get("approval_gates") or [g[0] for g in approval_entries(cfg)]
        print(f"approval    : {', '.join(gates)} -> {who} | {wired}")
    roles = subagent_roles(cfg)
    if roles:
        defs = agent_definitions()
        parts = []
        for r in roles:
            resolved, _ = resolve_subagent_role(r, defs)
            minted = "✓" if subwarrant_path(r).exists() else "no warrant (run `up`)"
            parts.append(f"{r} ({minted})" if resolved
                         else f"{r} (!! no agent definition)")
        print(f"subagents   : {', '.join(parts)}")
    s = _status_json()
    if s:
        cp = s.get("cp", {})
        runtime = _authorizer_status_line(cfg)
        ver = s.get("version")
        ver_bit = f" v{ver}" if ver else ""
        print(f"authorizer  : up ({authz_display()}) | {runtime}{ver_bit} | "
              f"cloud: {cp.get('status')} {cp.get('authorizer_id') or ''}")
    else:
        ep_mode, ep_loc = authz_endpoint()
        if ep_mode == "unix":
            # Managed socket authorizers are SYSTEM services, not started by `up`.
            print(f"authorizer  : down (unix {ep_loc}; restart the managed "
                  f"systemd/launchd service & check socket ownership)")
        else:
            print("authorizer  : down (run `tenuo-claude up`)")
    sink_fail = receipt_sink_failure()
    if sink_fail:
        print(f"receipts    : !! AUDIT SINK BROKEN — last error: {sink_fail}")
        print(f"              fix {RECEIPTS.parent} permissions/space; decisions are going unlogged")
    files = cloud_mode_files()
    if files["cloud_env"] and not files["cloud_state"]:
        print("cloud       : credentials present — run `tenuo-admin setup` then `tenuo-claude up`")
    elif mode := intended_mode(cfg):
        if mode == "cloud" and files["cloud_profile"]:
            print(f"cloud       : profile {CLOUD_PROFILE.name} merged")


# ---------------------------------------------------------------------------
# Audit / revoke / verify
# ---------------------------------------------------------------------------


def cmd_audit(args) -> None:
    if not RECEIPTS.exists():
        print("No receipts yet.")
        return
    raw_rows = [json.loads(x) for x in RECEIPTS.read_text().splitlines() if x.strip()]
    if getattr(args, "verify", False):
        ok, errors = verify_receipt_rows(raw_rows)
        if ok:
            print(f"Receipt verification OK ({len(raw_rows)} receipts)")
            for line in receipt_verify_summary_lines(raw_rows, ok=True):
                print(line)
        else:
            print("Receipt verification FAILED")
            for err in errors:
                print(f"  {err}")
            for line in receipt_verify_summary_lines(raw_rows, ok=False):
                print(line)
            raise SystemExit(1)
    rows = [_unwrap_receipt(r) for r in raw_rows]
    if getattr(args, "tail", None):
        rows = rows[-args.tail:]

    def arg_summary(row: dict) -> str:
        vals = row.get("args") or {}
        if not isinstance(vals, dict):
            return ""
        parts = []
        for key in ("file_path", "path", "url", "command", "target", "subagent_type"):
            val = vals.get(key)
            if val is not None:
                parts.append(f"{key}={val}")
        if parts:
            return "  " + " ".join(parts)
        if vals:
            return f"  args={json.dumps(vals, sort_keys=True)}"
        return ""

    for r in rows:
        if r.get("phase") == "post":
            print(f"  · outcome  {r.get('claude_tool',''):14} {r.get('outcome_preview','')[:60]}")
        else:
            d = r.get("decision", "")
            # In observe-only mode a "deny" was logged but NOT enforced.
            if d == "pending":
                mark = "PENDING"   # parked on human approval
            elif r.get("shadow") and d == "deny":
                mark = "WOULD-DENY"
            else:
                mark = "ALLOW" if d == "allow" else "DENY "
            src = ("appr" if r.get("source") == "approval"
                   else "mcp" if r.get("source") == "mcp_proxy"
                   else "gov" if r.get("governed") else "aud")
            who = f" <{r['agent_type']}>" if r.get("agent_type") else ""
            print(f"  {mark:10} [{src}] {r.get('claude_tool',''):14}{who} -> "
                  f"{r.get('tenuo_tool','')}  {r.get('reason','')}{arg_summary(r)}")


def cmd_revoke(_args) -> None:
    cfg = load_config()
    if not STATE_JSON.exists():
        raise SystemExit("Run `tenuo-claude init` first.")
    st = json.loads(STATE_JSON.read_text())
    wid = st["warrant_id"]
    env = runtime_env()
    creds = cloud_creds(cfg)
    cloud = bool(creds.get("url") and creds.get("api_key"))
    if cloud:
        url = creds["url"]
        print(f"Cloud mode. Revoke from the dashboard or an admin key:\n"
              f"  curl -X POST {url}/v1/revocations \\\n"
              f"    -H \"Authorization: Bearer $ADMIN_API_KEY\" -H 'Content-Type: application/json' \\\n"
              f"    -d '{{\"warrant_id\":\"{wid}\",\"reason\":\"revoked\"}}'\n"
              f"The authorizer pulls the new SRL within one heartbeat; next call is denied.")
        return
    from tenuo import SigningKey, SignedRevocationList

    issuer = SigningKey.from_bytes(base64.b64decode(ISSUER_KEY.read_text()))
    b = SignedRevocationList.builder()
    b.revoke(wid)
    b.version(int(time.time()))
    SRL.write_bytes(bytes(b.build(issuer).to_bytes()))
    print(f"Revoked {wid} locally. Restarting authorizer to load the SRL…")
    cmd_down(_args)
    cmd_up(_args)


def check_claude_hook_exit_contract() -> bool:
    """Live-check Claude Code PreToolUse semantics: exit 1 proceeds, exit 2 blocks."""
    claude = shutil.which("claude")
    if not claude:
        print("  .. hook-exit  claude not in PATH — skipped (install Claude Code to verify)")
        return True
    try:
        ver = subprocess.run([claude, "--version"], capture_output=True, text=True, timeout=15)
        version = (ver.stdout or ver.stderr or "").strip().splitlines()[0]
    except Exception as exc:
        print(f"  .. hook-exit  could not read claude --version ({exc}) — skipped")
        return True
    print(f"  .. hook-exit  live harness ({version})")

    with tempfile.TemporaryDirectory(prefix="tenuo-hook-exit-") as tmp:
        root = Path(tmp)
        canary = root / "CANARY.txt"
        canary.write_text("TENUO_HOOK_CANARY")
        claude_dir = root / ".claude"
        claude_dir.mkdir()

        def run_with_hook(exit_code: int) -> tuple[subprocess.CompletedProcess, Path]:
            marker = root / f"hook_ran_{exit_code}.txt"
            marker.unlink(missing_ok=True)
            hook = root / f"hook_exit{exit_code}.py"
            hook.write_text(
                "import sys\n"
                f"from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('exit={exit_code}\\n')\n"
                f"sys.exit({exit_code})\n")
            settings = {
                "hooks": {
                    "PreToolUse": [{
                        "matcher": "Read",
                        "hooks": [{"type": "command",
                                   "command": f'"{sys.executable}" "{hook}"'}],
                    }]
                }
            }
            (claude_dir / "settings.json").write_text(json.dumps(settings))
            proc = subprocess.run(
                [claude, "-p",
                 "Read CANARY.txt. Reply with only the file contents, nothing else.",
                 "--dangerously-skip-permissions"],
                cwd=root, capture_output=True, text=True, timeout=90)
            return proc, marker

        try:
            r1, m1 = run_with_hook(1)
            r2, m2 = run_with_hook(2)
        except subprocess.TimeoutExpired:
            print("  .. hook-exit  claude timed out — skipped (API/network?)")
            return True
        except Exception as exc:
            print(f"  .. hook-exit  claude harness error ({exc}) — skipped")
            return True

        ok = True
        for exit_code, proc, marker in ((1, r1, m1), (2, r2, m2)):
            out = (proc.stdout or "") + (proc.stderr or "")
            leaked = "TENUO_HOOK_CANARY" in out
            ran = marker.is_file()
            if not ran:
                print(f"  XX hook-exit  exit {exit_code}: hook never ran "
                      f"(project settings not loaded? trust prompt?)")
                print("      → Open/trust the project in Claude Code first, or use "
                      "`tenuo-claude verify --deep --no-live` for policy-only checks.")
                ok = False
                continue
            if exit_code == 1:
                if leaked:
                    print("  ok  hook-exit  exit 1 is non-blocking (canary reached)")
                else:
                    print("  XX hook-exit  exit 1 blocked unexpectedly — contract may have changed")
                    ok = False
            elif leaked:
                print("  XX hook-exit  exit 2 did NOT block (canary leaked)")
                ok = False
            else:
                print("  ok  hook-exit  exit 2 blocks the tool call")
        return ok


def cmd_verify(args) -> None:
    """Policy-driven authorizer self-test from tenuo.yaml."""
    cfg = load_config()
    apply_transport_env(cfg)
    if not _status_json():
        mode, loc = authz_endpoint()
        if mode == "unix":
            # The socket is served by the SYSTEM-managed daemon, not `up` (which only
            # starts the user-scoped TCP authorizer). Point the admin at the service.
            raise SystemExit(
                f"No authorizer on unix socket {loc}. (Re)install/restart the managed "
                "authorizer service (Linux: `systemctl restart tenuo-authorizer`; macOS: "
                "`launchctl kickstart -k system/com.tenuo.authorizer`) and verify the socket "
                "is root-owned under a root-owned dir — not `tenuo-claude up`.")
        raise SystemExit("Authorizer not running. Run `tenuo-claude up` first.")
    deep = getattr(args, "deep", False)
    probes, _ = build_probes(cfg, deep=deep)
    roles = subagent_roles(cfg)

    def decide(tool, tin, role):
        allowed, reason, _, _ = authorize_call(cfg, tool, tin, role, roles, live=False)
        return allowed, reason

    ok, results = run_probes(probes, decide)
    extra: list[str] = []

    if roles:
        extra.append("  [subagent wiring]")
        defs = agent_definitions()
        for role in roles:
            resolved, where = resolve_subagent_role(role, defs)
            ok = ok and resolved
            mark = "ok" if resolved else "XX"
            detail = where if resolved else (
                f"NO agent definition — add .claude/agents/{role}.md or rename to a real subagent_type")
            extra.append(f"    {mark} role {role} -> {detail}")

    if has_approval_gates(cfg):
        extra.append("  [approval]")
        st = load_cloud_state()
        pid = approval_policy_id(cfg)
        cloud_cfg = cfg.get("cloud") or {}
        approver = (st.get("web_fetch_approver") or cloud_cfg.get("approver_identity")
                    or cloud_cfg.get("approver_identity_id"))
        cloud_ready = bool((cfg.get("cloud") or {}).get("url") and pid)
        ok = ok and (bool(pid) if cloud_ready else True)
        gates = st.get("approval_gates") or [g[0] for g in approval_entries(cfg)]
        extra.append(
            f"    {'ok' if pid else '..'} policy {pid or 'not set up (run tenuo-admin setup)'}"
            f"{f'  approver={approver}' if approver else ''}  gates={', '.join(gates)}")
        if webfetch_approval(cfg):
            allowed, reason, _, _ = authorize_call(
                cfg, "WebFetch", {"url": "https://example.com/data"}, None, roles, live=False)
            gated = (not allowed) and reason.startswith(APPROVAL_PENDING_REASON)
            if cloud_ready:
                ok = ok and gated
                extra.append(
                    f"    {'ok' if gated else 'XX'} web_fetch off-allowlist -> "
                    f"{'approval required' if gated else 'NOT gated (' + reason + ')'}")
            else:
                extra.append(
                    f"    .. web_fetch off-allowlist denied locally (approval is Cloud-only): {reason}")
        mcp_gated = {
            tool: parsed for tool, parsed in mcp_enforce_entries(cfg).items() if parsed.get("approval")}
        if "delete_deployment" in mcp_gated:
            allowed, reason, _, _ = authorize_call(
                cfg, "delete_deployment", {"target": "production"}, None, roles, live=False)
            gated = (not allowed) and reason.startswith(APPROVAL_PENDING_REASON)
            if cloud_ready:
                ok = ok and gated
                extra.append(
                    f"    {'ok' if gated else 'XX'} delete_deployment production -> "
                    f"{'approval required' if gated else 'NOT gated (' + reason + ')'}")
            else:
                extra.append(
                    f"    .. delete_deployment production denied locally (approval is Cloud-only): {reason}")
            allowed, reason, _, _ = authorize_call(
                cfg, "delete_deployment", {"target": "staging"}, None, roles, live=False)
            if cloud_ready:
                ok = ok and allowed
                extra.append(
                    f"    {'ok' if allowed else 'XX'} delete_deployment staging -> "
                    f"{'allowed (exempt)' if allowed else reason}")

    mode, loc = authz_endpoint()
    extra.append("  [transport]")
    if mode == "unix":
        managed = managed_mode(cfg)
        safe, why = _safe_managed_socket(loc, managed=managed)
        # In managed mode an untrusted socket is a hard failure: the whole point is
        # to stop trusting an unauthenticated responder. Unmanaged, it's advisory.
        if managed:
            ok = ok and safe
        extra.append(f"    {'ok' if safe else 'XX'} unix socket {loc} -> {why}")
    else:
        managed = managed_mode(cfg)
        # Managed mode on loopback TCP can't authenticate the responder.
        extra.append(
            f"    {'!!' if managed else 'ok'} tcp {loc}"
            + ("  (managed mode should use a unix socket; loopback TCP is unauthenticated)"
               if managed else ""))

    if deep and not getattr(args, "no_live", False):
        ok = ok and check_claude_hook_exit_contract()
    elif deep:
        extra.append("  .. hook-exit  skipped (--no-live)")

    format_text(cfg, results, extra_lines=extra, overall_ok=ok)
    raise SystemExit(0 if ok else 1)


def cmd_doctor(args) -> None:
    print("note: `doctor` is deprecated — use `tenuo-claude verify` "
          "(add `--deep` for SSRF / hook canary).", file=sys.stderr)
    cmd_verify(argparse.Namespace(deep=True, no_live=getattr(args, "no_live", False)))


def cmd_demo(args) -> None:
    """Run tenuo_demo.py in the project directory, if present."""
    demo_script = DEMO_DIR / "tenuo_demo.py"
    if not demo_script.is_file():
        raise SystemExit(
            "No scripted tour in this project (tenuo_demo.py).\n"
            "  tenuo-claude verify     policy self-test against your tenuo.yaml\n"
            "  Reference demo: https://github.com/tenuo-ai/tenuo-claude-code/tree/main/demo")
    cmd = [sys.executable, str(demo_script)]
    if getattr(args, "advanced", False):
        cmd.append("--advanced")
    if getattr(args, "live_approval", False):
        cmd.append("--live-approval")
    raise SystemExit(subprocess.run(cmd, cwd=DEMO_DIR).returncode or 0)


def _bench_percentile(sorted_ms: list[float], pct: float) -> float:
    if not sorted_ms:
        return 0.0
    idx = min(len(sorted_ms) - 1, max(0, int(len(sorted_ms) * pct / 100)))
    return sorted_ms[idx]


def _bench_summary(samples_ms: list[float]) -> dict:
    if not samples_ms:
        return {"n": 0, "min": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0}
    ordered = sorted(samples_ms)
    return {
        "n": len(ordered),
        "min": ordered[0],
        "p50": statistics.median(ordered),
        "p95": _bench_percentile(ordered, 95),
        "max": ordered[-1],
    }


def _bench_run(label: str, fn, *, iterations: int, warmup: int) -> dict:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return {"label": label, **_bench_summary(samples)}


def _bench_pop_sign_ms(tenuo_tool: str, sign_args: dict, warrant_b64: str | None = None) -> None:
    from tenuo import SigningKey
    from tenuo_core import decode_warrant_stack_base64

    holder = SigningKey.from_bytes(base64.b64decode(HOLDER_KEY.read_text()))
    header_b64 = warrant_b64 if warrant_b64 is not None else WARRANT.read_text()
    leaf = decode_warrant_stack_base64(header_b64)[-1]
    leaf.sign(holder, tenuo_tool, sign_args, int(time.time()))


def cmd_bench(args) -> None:
    """Measure per-tool-call overhead (PoP sign, authorizer RTT, hook path)."""
    if not _status_json():
        raise SystemExit("Authorizer not running. Run `tenuo-claude up` first.")
    cfg = load_config()
    sb = cfg["_sandbox_abs"]
    Path(sb).mkdir(parents=True, exist_ok=True)
    probe = Path(sb) / ".tenuo_bench_probe"
    probe.write_text("bench\n")
    roles = subagent_roles(cfg)
    iterations = max(1, int(getattr(args, "iterations", 100)))
    warmup = max(0, int(getattr(args, "warmup", 10)))
    include_hook = not getattr(args, "no_hook", False)

    read_args = {"file_path": str(probe)}
    read_sign = {"path": os.path.realpath(os.path.abspath(read_args["file_path"]))}
    bash_args = {"command": "ls -la"}
    bash_sign = {"command": "ls -la"}

    scenarios: list[tuple[str, object]] = [
        ("PoP sign (session warrant)", lambda: _bench_pop_sign_ms("read_file", read_sign)),
        ("Authorizer /verify/read_file (allow)", lambda: authorize(
            "read_file", "/verify/read_file", read_sign, read_sign)),
        ("authorize_call Read (allow)", lambda: authorize_call(
            cfg, "Read", read_args, None, roles)),
        ("authorize_call Bash (allow)", lambda: authorize_call(
            cfg, "Bash", bash_args, None, roles)),
        ("authorize_call WebSearch (audit-allow)", lambda: authorize_call(
            cfg, "WebSearch", {"query": "bench"}, None, roles)),
    ]
    if roles:
        role = next(iter(roles))
        sw = subwarrant_path(role)
        if sw.exists():
            scenarios.insert(1, (
                f"PoP sign (subagent:{role})",
                lambda r=role, s=sw.read_text(): _bench_pop_sign_ms(
                    "read_file", read_sign, warrant_b64=s)))
            scenarios.append((
                f"authorize_call Read (subagent:{role})",
                lambda r=role: authorize_call(
                    cfg, "Read", read_args, r, roles)))

    results = [_bench_run(label, fn, iterations=iterations, warmup=warmup)
               for label, fn in scenarios]

    if include_hook:
        hook_event = json.dumps({
            "tool_name": "Read",
            "tool_input": read_args,
        })
        hook_cmd, hook_args = wiring_command_parts("_hook")
        hook_argv = [hook_cmd, *hook_args]

        def run_hook_subprocess() -> None:
            proc = subprocess.run(
                hook_argv,
                input=hook_event,
                text=True,
                capture_output=True,
                cwd=DEMO_DIR,
                timeout=30,
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or f"hook exit {proc.returncode}")

        hook_label = shlex.join(hook_argv)
        results.append(_bench_run(
            f"Hook subprocess ({hook_label})", run_hook_subprocess,
            iterations=max(5, iterations // 10), warmup=min(warmup, 3)))

    payload = {
        "iterations": iterations,
        "warmup": warmup,
        "authorizer": resolve_authz_url(),
        "mode": cfg.get("mode", "enforce"),
        "subagents": bool(roles),
        "results": results,
    }

    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
        return

    print(f"Tenuo overhead bench  (iterations={iterations}, warmup={warmup})")
    print(f"  authorizer : {resolve_authz_url()}")
    print(f"  mode       : {cfg.get('mode', 'enforce')}"
          f"{'  subagents: yes' if roles else ''}")
    print()
    print(f"{'Scenario':<42} {'p50':>8} {'p95':>8} {'max':>8}")
    print("-" * 68)
    for row in results:
        print(f"{row['label']:<42} {row['p50']:7.2f}ms {row['p95']:7.2f}ms {row['max']:7.2f}ms")
    print()
    print("Notes:")
    print("  • PoP sign = local Ed25519 + warrant decode (no network).")
    print("  • Authorizer row = sign + HTTP round-trip to localhost.")
    print("  • authorize_call = route resolution + authorizer (typical hook core).")
    if include_hook:
        print("  • Hook subprocess = full PreToolUse path incl. Python cold start per call.")
    print("  • Compare p50 on a quiet machine; authorizer RTT dominates on hot paths.")
    print("  • Core chain-verify microbenches: tenuo-core `cargo bench --bench warrant_benchmarks`.")


def _pack_summary_line(pack: packs.Pack) -> str:
    s = pack.summary
    return (
        f"{s.get('tools', 0)} tools: {s.get('allowed', 0)} allowed, "
        f"{s.get('gated', 0)} gated on approval, {s.get('denied', 0)} denied"
    )


def _print_pack_header(pack: packs.Pack) -> None:
    pin = pack.pinned
    print(f"{pack.name} pack {pack.display_version} (reviewed {pack.reviewed})")
    print(
        f"pinned to {pin.get('name')} {pin.get('version')}, "
        f"tool-list hash {pin.get('tool_list_hash')}"
    )


def cmd_pack(args) -> None:
    action = getattr(args, "pack_cmd", None)
    if action == "list":
        all_packs = packs.list_packs()
        if not all_packs:
            print("No bundled policy packs found.")
            return
        for pack in all_packs:
            print(f"{pack.name:<16} {pack.display_version:<4} {_pack_summary_line(pack)}")
        return
    if action == "inspect":
        pack = packs.load_pack(args.name)
        _print_pack_header(pack)
        if pack.description:
            print()
            print(pack.description.strip())
        print()
        print(_pack_summary_line(pack))
        if pack.params:
            print("\nParameters:")
            for p in pack.params:
                example = f" ({p.get('example')})" if p.get("example") else ""
                print(f"  - {p['name']}: {p.get('prompt', p['name'])}{example}")
        if pack.assumptions:
            print("\nAssumptions:")
            for a in pack.assumptions:
                print(f"  - {a}")
        return
    raise SystemExit("Usage: tenuo-claude pack list | pack inspect <name>")


def render_policy_pack(args) -> None:
    pack = packs.load_pack(args.pack)
    _print_pack_header(pack)
    print()
    print(f"This pack needs {len(pack.params)} decision(s) from you:")
    supplied = packs.parse_param_overrides(getattr(args, "param", None))
    params = packs.collect_params(pack, supplied, assume_defaults=getattr(args, "yes", False))
    dest = packs.write_pack_policy(DEMO_DIR, pack, params, force=getattr(args, "force", False))
    print()
    print(f"Wrote {dest.name} (mode: dry-run)")
    print(_pack_summary_line(pack))
    print("Run your agent normally. `tenuo-claude audit` shows what WOULD have been denied.")


def cmd_init(args) -> None:
    # `init` compiles an EXISTING policy; it no longer writes one by default.
    # Scaffolding belongs to the first-run path (`onboard`, or `init --scaffold`).
    # This avoids silently dropping an example policy into a project you're
    # integrating into. `--no-scaffold` is kept as a hidden no-op for back-compat.
    if getattr(args, "pack", None):
        render_policy_pack(args)
    elif getattr(args, "scaffold", False):
        scaffold_example_policy(DEMO_DIR)
    elif not CONFIG_FILE.exists():
        raise SystemExit(
            "No tenuo.yaml here — `init` compiles an existing policy, it doesn't write one.\n"
            "  • guided setup:     tenuo-claude onboard\n"
            "  • use a pack:       tenuo-claude init --pack github-mcp\n"
            "  • write an example: tenuo-claude init --scaffold\n"
            "  • or add your own tenuo.yaml, then re-run `init`")
    if getattr(args, "local", False):
        moved = disable_cloud_artifacts()
        if moved:
            print("Local mode — moved aside:", ", ".join(moved))
    elif getattr(args, "cloud", False):
        url = getattr(args, "cloud_url", None)
        if not url and CLOUD_ENV.exists():
            creds = cloud_creds(load_config())
            url = creds.get("url")
        write_cloud_profile(url=url or "https://api.tenuo.ai")
        print(f"Cloud profile written: {CLOUD_PROFILE.name}")
        if getattr(args, "advanced", False) or getattr(args, "demo", False):
            approver = getattr(args, "approver", None)
            approver_id = getattr(args, "approver_id", None)
            if not approver and not approver_id:
                raise SystemExit("--advanced requires --approver-id or --approver.")
            write_advanced_profile(approver=approver, approver_id=approver_id)
            print(f"Advanced profile written: {ADVANCED_PROFILE.name}")
        if not CLOUD_ENV.exists() and CLOUD_ENV_EXAMPLE.exists():
            print(f"Next: copy {CLOUD_ENV_EXAMPLE.name} → .state/cloud.env and paste Quick Connect token")
    if (getattr(args, "advanced", False) or getattr(args, "demo", False)) and not getattr(args, "cloud", False):
        approver = getattr(args, "approver", None)
        approver_id = getattr(args, "approver_id", None)
        if not approver and not approver_id:
            raise SystemExit("--advanced requires --approver-id or --approver.")
        write_advanced_profile(approver=approver, approver_id=approver_id)
        print(f"Advanced profile written: {ADVANCED_PROFILE.name} — re-run `tenuo-admin setup`")
    cfg = load_config()
    info = generate(cfg)
    _ensure_state_in_gitignore()
    print("Initialized tenuo-claude.")
    print(f"  warrant  : {info['warrant_id']}")
    print(f"  sandbox  : {info['sandbox']}")
    print(f"  wired    : .claude/settings.json (PreToolUse/PostToolUse), .mcp.json, .state/gateway.yaml")
    print("Next: `tenuo-claude up` then use Claude Code in this directory.")


def _ensure_state_in_gitignore() -> None:
    """Add .state/ to .gitignore if not already present, and warn if tracked."""
    gitignore_path = DEMO_DIR / ".gitignore"
    state_dir = DEMO_DIR / ".state"

    # Check if .state/ is already tracked in git
    try:
        result = subprocess.run(
            ["git", "ls-files", ".state/"],
            cwd=DEMO_DIR,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            print(
                f"WARNING: .state/ is tracked in git and contains private keys and credentials.\n"
                f"  Run: git rm -r --cached .state/\n"
                f"  Then commit: git commit -m 'Stop tracking .state/ directory'",
                file=sys.stderr
            )
    except Exception:
        pass  # git not available or in non-git directory

    # Add .state/ to .gitignore if not present
    try:
        gitignore_text = gitignore_path.read_text() if gitignore_path.exists() else ""
        if ".state/" not in gitignore_text and ".state" not in gitignore_text:
            # Append .state/ to .gitignore
            with gitignore_path.open("a") as f:
                if gitignore_text and not gitignore_text.endswith("\n"):
                    f.write("\n")
                f.write(".state/  # Tenuo: private keys, warrants, Cloud credentials\n")
    except Exception as e:
        print(f"warning: could not update .gitignore: {e}", file=sys.stderr)


def cmd_refresh(args) -> None:
    cfg = load_config()
    creds = cloud_creds(cfg)
    use_trigger = use_cloud_trigger(cfg)
    was_running = authorizer_running(cfg)

    wid = refresh_policy(cfg)
    managed = managed_mode(cfg)
    print("Refreshed local overlay and wiring:" if managed else "Refreshed from tenuo.yaml:")
    print(f"  warrant  : {wid}")
    print(f"  gateway  : .state/{GATEWAY.name}")
    print(f"  wiring   : .claude/settings.json, .mcp.json")
    print(f"  posture  : {'dry-run (observe-only)' if is_audit_mode(cfg) else 'enforce'}")
    for w in posture_warnings(cfg):
        print(f"  !! {w}")
    if managed:
        tid = trigger_id(cfg) or "?"
        print(f"  authority: unchanged — Cloud trigger {tid} (cloud root only)")
        print("  note     : managed mode — local capability edits do NOT change Cloud")
        print("             authority; they only narrow routing/UI. Capability changes")
        print("             require admin/CI: tenuo-admin setup.")
        for line in _attenuation_notice(cfg):
            print(f"  {line}")
    if use_trigger:
        # In Cloud mode, warrant capabilities come from the TRIGGER, not this
        # refresh. Detect whether the capability-bearing policy actually drifted
        # from what `tenuo-admin setup` last baked in, and warn LOUDLY only then —
        # a blanket note on every refresh trained users to ignore it.
        baked = load_cloud_state().get("policy_fingerprint")
        current = policy_capability_fingerprint(cfg)
        if baked and baked != current:
            print()
            print("  !! POLICY DRIFT — enforce/audit/mcp/subagent/approval rules changed since the")
            print("     last `tenuo-admin setup`. Cloud warrants come from the TRIGGER, so this")
            print("     refresh did NOT apply those changes. They will NOT take effect until you:")
            print("         tenuo-admin setup")
        elif not baked:
            print("  note     : Cloud mode — capability changes (enforce/audit/mcp/subagent/approval)")
            print("             take effect only after `tenuo-admin setup` (run it once to enable")
            print("             drift detection on future refreshes).")

    if was_running and not getattr(args, "no_restart", False):
        print("Restarting authorizer (reload gateway)…")
        cmd_down(args)
        cmd_up(args)
    elif was_running:
        print("Authorizer left running (--no-restart). Run `down` then `up` to reload gateway.")
    else:
        print("Next: `tenuo-claude up`")


# ---------------------------------------------------------------------------
# Managed-mode templates (enterprise / MDM)
#
# These artifacts are what make managed Cloud mode enforceable against a
# non-cooperative developer (threat T6): the `cloud.managed` flag and the
# CLI's fail-closed behavior are cooperative ergonomics, but only an
# org-deployed, highest-precedence settings tier plus a system-pinned
# authorizer trust anchor actually prevent bypass. We GENERATE them (rather
# than ship static files) because the hook command is machine-specific and
# must resolve on every endpoint — a hand-written command is the #1 footgun.
# ---------------------------------------------------------------------------

MANAGED_SETTINGS_NAME = "managed-settings.json"
MANAGED_MCP_NAME = "managed-mcp.json"
SYSTEMD_UNIT_NAME = "tenuo-authorizer.service"
LAUNCHD_PLIST_NAME = "com.tenuo.authorizer.plist"
AUTHZ_ENV_NAME = "authorizer.env"

# Where Claude Code reads file-based managed settings (outrank user/project/CLI).
MANAGED_SETTINGS_PATHS = {
    "macOS": "/Library/Application Support/ClaudeCode/managed-settings.json",
    "Linux/WSL": "/etc/claude-code/managed-settings.json",
    "Windows": r"C:\Program Files\ClaudeCode\managed-settings.json",
}

_ROOT_PLACEHOLDER = "REPLACE_WITH_TENANT_ROOT_HEX"
_URL_PLACEHOLDER = "REPLACE_WITH_CONTROL_PLANE_URL"
_NATIVE_BIN_PLACEHOLDER = "REPLACE_WITH_AUTHORIZER_BINARY"
# Where the gateway config is deployed for a managed host (read-only, no keys).
_MANAGED_GATEWAY = "/etc/tenuo/gateway"


def managed_claude_settings(cfg: dict) -> dict:
    """Highest-precedence Claude Code ``managed-settings.json`` that pins Tenuo.

    Locks the fleet so a developer cannot remove, replace, or bypass governance:
      - the Tenuo PreToolUse/PostToolUse hooks are pinned to the exact fail-closed
        command we wire locally (absolute, ``/bin/sh``-guarded on POSIX);
      - ``allowManagedHooksOnly`` blocks any user/project hook from loading;
      - ``permissions.disableBypassPermissionsMode`` kills
        ``--dangerously-skip-permissions``;
      - ``allowManagedPermissionRulesOnly`` stops local allow/ask rules from
        loosening policy;
      - when an MCP proxy is configured, only the managed Tenuo server is admitted.
    """
    hook_timeout = APPROVAL_POLL_SECONDS + 30 if has_approval_gates(cfg) else 30
    settings: dict = {
        "hooks": {
            # `_managed-hook` (not `_hook`): enforcement is anchored here in the
            # MDM-pinned command, so local `mode: dry-run` / flag edits cannot
            # downgrade a managed endpoint to observe-only.
            "PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": hook_wiring_command_string("_managed-hook"),
                 "timeout": hook_timeout}]}],
            "PostToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": wiring_command_string("_post")}]}],
        },
        "allowManagedHooksOnly": True,
        "allowManagedPermissionRulesOnly": True,
        # Documented as the string "disable" (not a boolean). Both are part of the
        # ENTERPRISE.md baseline: forbid --dangerously-skip-permissions AND the
        # auto-accept permission mode, so the agent can't self-approve around hooks.
        "permissions": {"disableBypassPermissionsMode": "disable",
                        "disableAutoMode": "disable"},
    }
    if mcp_wiring(cfg):
        settings["allowManagedMcpServersOnly"] = True
        settings["allowedMcpServers"] = [{"serverName": MCP_SERVER_NAME}]
    return settings


def managed_mcp_config(cfg: dict) -> dict | None:
    """``managed-mcp.json``: the Tenuo proxy as the admin-deployed MCP server.

    Returns None when the policy declares no downstream MCP server. A deployed
    managed-mcp.json takes exclusive control of MCP, so the agent can only reach
    the governed proxy. Unlike `mcp_wiring`, this pins the ``_managed-mcp-proxy``
    entrypoint so enforcement is anchored in the managed artifact (local
    ``mode: dry-run`` / flag edits cannot make it forward denied calls).
    """
    if not cfg.get("mcp", {}).get("downstream"):
        return None
    cmd, args = wiring_command_parts("_managed-mcp-proxy")
    return {"mcpServers": {MCP_SERVER_NAME: {"command": cmd, "args": args}}}


def _template_root(cfg: dict) -> str:
    """Resolve the tenant CLOUD ROOT for the authorizer trust anchor, offline.

    Never derived from a warrant (see fire_session_warrant). Falls back to a
    loud placeholder so a misconfigured template fails obviously, not silently.
    """
    return (cloud_creds(cfg).get("root") or load_cloud_state().get("root")
            or _ROOT_PLACEHOLDER)


def _cfg_authorizer(cfg: dict) -> dict:
    """The ``authorizer`` sub-dict, created (and attached) if missing/malformed.

    Lets callers mutate ``cfg["authorizer"]`` keys without repeating the
    get-or-create dance.
    """
    az = cfg.get("authorizer")
    if not isinstance(az, dict):
        az = {}
        cfg["authorizer"] = az
    return az


def _authz_socket_flags(cfg: dict) -> list[str]:
    """Connect-permission flags (``serve``) for the root-owned managed socket.

    The socket is ALWAYS root-owned — that ownership, not the connect mode, is the
    trust boundary (`_safe_managed_socket`). The default ``0666`` is world-
    connectable so the unprivileged Claude hook can reach it. Enterprises that want
    to tighten CONNECT without hand-editing units set ``authorizer.socket_group``:
    the socket then uses ``0660`` and is connectable only by that group.
    """
    authz = cfg.get("authorizer") or {}
    group = authz.get("socket_group")
    mode = "0660" if group else "0666"
    flags = ["--socket-mode", mode]
    if group:
        flags += ["--socket-group", str(group)]
    return flags


def _authz_docker_argv(cfg: dict) -> list[str]:
    """``docker`` arguments for a system-managed authorizer.

    The crux of the managed trust model lives here: ``TENUO_TRUSTED_KEYS`` is the
    tenant CLOUD ROOT *only* — no local issuer is ever appended, so a
    locally-minted warrant cannot verify. Secrets (the runtime key) come from an
    ``--env-file`` so they never land in the unit/plist. The pinned image tag is
    the version floor; do not float to ``:latest``.
    """
    url = cloud_creds(cfg).get("url") or _URL_PLACEHOLDER
    sock_dir = os.path.dirname(DEFAULT_AUTHZ_SOCKET)
    # Serve on a root-owned Unix socket, NOT loopback TCP: the hook authenticates
    # the responder by file ownership (see `_safe_managed_socket`), which a port
    # cannot provide. No `-p` publish: there is no TCP surface to race.
    #
    # `-u 0:0` is REQUIRED: the image's default user is uid 1000, but systemd creates
    # the socket's RuntimeDirectory root-owned 0755, which a non-root container user
    # cannot write to (it fails with EACCES on socket bind). Forcing root lets the
    # daemon create the socket AND makes the bind-mounted socket root-owned on the
    # host — exactly the ownership `_safe_managed_socket(managed=True)` trusts. A
    # 1000-owned dir would be insecure on a typical workstation where the developer
    # IS uid 1000 and could replace the socket.
    #
    # `--socket-mode 0666` (default): the socket stays root-OWNED (the trust anchor),
    # but the unprivileged Claude hook must be able to CONNECT. Connect permission is
    # not the trust boundary — the authorizer authorizes by warrant/PoP, and only root
    # could have placed a root-owned socket under the root-owned dir — so 0666 is safe.
    # Set `authorizer.socket_group` to tighten to a group (mode 0660); see
    # `_authz_socket_flags`.
    return [
        "run", "--rm", "--name", "tenuo-authorizer",
        "-u", "0:0",
        "-v", "/etc/tenuo/gateway:/state:ro",
        "-v", f"{sock_dir}:{sock_dir}",
        "--env-file", f"/etc/tenuo/{AUTHZ_ENV_NAME}",
        "-e", f"TENUO_TRUSTED_KEYS={_template_root(cfg)}",
        "-e", f"TENUO_CONTROL_PLANE_URL={url}",
        "-e", f"TENUO_AUTHORIZER_NAME={cfg.get('name', 'tenuo-claude')}",
        authorizer_image(cfg),
        "serve", "--config", f"/state/{GATEWAY.name}",
        "--socket", DEFAULT_AUTHZ_SOCKET, *_authz_socket_flags(cfg),
    ]


def authorizer_env_template(_cfg: dict) -> str:
    return (
        "# Tenuo authorizer runtime secrets — root-owned, chmod 0600.\n"
        "# Use a RUNTIME / service-account key only. NEVER an admin key here\n"
        "# (separation of duties: the runtime plane only fires triggers / consumes\n"
        "# warrants).\n"
        "TENUO_API_KEY=REPLACE_WITH_RUNTIME_KEY\n"
        "# Or, instead of TENUO_API_KEY, a Quick Connect token:\n"
        "# TENUO_CONNECT_TOKEN=REPLACE_WITH_CONNECT_TOKEN\n"
    )


def systemd_unit_template(cfg: dict) -> str:
    docker_cmd = "/usr/bin/docker " + " ".join(shlex.quote(a) for a in _authz_docker_argv(cfg))
    runtime_dir = os.path.basename(os.path.dirname(DEFAULT_AUTHZ_SOCKET))  # e.g. "tenuo" -> /run/tenuo
    # RuntimeDirectory creates /run/<dir> (== /var/run/<dir>) owned by root, 0755,
    # before ExecStart and tears it down on stop — so the socket the hook trusts
    # always lives under a root-owned, non-world-writable directory.
    return f"""[Unit]
Description=Tenuo Authorizer (managed, cloud-root-only)
After=network-online.target docker.service
Wants=network-online.target

[Service]
RuntimeDirectory={runtime_dir}
RuntimeDirectoryMode=0755
ExecStartPre=-/usr/bin/docker rm -f tenuo-authorizer
ExecStart={docker_cmd}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
"""


def _template_native_bin(cfg: dict) -> str:
    """Path to the native authorizer binary for a host (non-Docker) managed daemon.

    macOS needs this: Docker Desktop runs the container inside a Linux VM, so a UDS
    the container creates is not a macOS-kernel socket the Claude hook can connect
    to. A macOS managed rollout must therefore run a NATIVE host authorizer that owns
    the macOS socket directly. Falls back to a loud placeholder.
    """
    return (cfg.get("authorizer") or {}).get("binary") or _NATIVE_BIN_PLACEHOLDER


def launchd_plist_template(cfg: dict) -> str:
    sock_dir = os.path.dirname(DEFAULT_AUTHZ_SOCKET)
    q = shlex.quote
    # macOS runs the authorizer NATIVELY (not via Docker): a container UDS lives in
    # the Linux VM and is unreachable from the macOS host, so a Docker-backed managed
    # rollout would fail closed. The LaunchDaemon runs as root, so it creates the
    # socket dir root-owned (0755), sources the root-owned env-file for the runtime
    # key, and execs the native authorizer with the cloud-root-only trust anchor.
    env_file = f"/etc/tenuo/{AUTHZ_ENV_NAME}"
    cfg_path = f"{_MANAGED_GATEWAY}/{GATEWAY.name}"
    # Root-OWNED socket (the trust anchor) that the unprivileged hook can still
    # connect to. See _authz_docker_argv / _authz_socket_flags for why connect != trust.
    socket_flags = " ".join(q(f) for f in _authz_socket_flags(cfg))
    serve = (f"env TENUO_TRUSTED_KEYS={q(_template_root(cfg))} "
             f"TENUO_CONTROL_PLANE_URL={q(cloud_creds(cfg).get('url') or _URL_PLACEHOLDER)} "
             f"TENUO_AUTHORIZER_NAME={q(cfg.get('name', 'tenuo-claude'))} "
             f"{q(_template_native_bin(cfg))} serve --config {q(cfg_path)} "
             f"--socket {q(DEFAULT_AUTHZ_SOCKET)} {socket_flags}")
    wrapper = (f"mkdir -p {q(sock_dir)} && chmod 0755 {q(sock_dir)} && "
               f"set -a && . {q(env_file)} && exec {serve}")
    argv = ["/bin/sh", "-c", wrapper]
    args_xml = "\n".join(f"    <string>{a}</string>" for a in argv)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.tenuo.authorizer</string>
  <key>ProgramArguments</key>
  <array>
{args_xml}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
"""


def _managed_artifacts(cfg: dict, platform: str = "all") -> dict[str, str]:
    """Ordered {filename: contents} for managed-mode artifacts.

    ``platform`` scopes the OS-specific service unit so a fleet rollout gets only the
    artifacts it needs: ``linux`` emits the systemd unit (Docker), ``macos`` emits the
    launchd plist (native authorizer), ``all`` emits both. The settings, MCP and env
    artifacts are platform-agnostic and always included.
    """
    out = {MANAGED_SETTINGS_NAME: json.dumps(managed_claude_settings(cfg), indent=2) + "\n"}
    mcp = managed_mcp_config(cfg)
    if mcp:
        out[MANAGED_MCP_NAME] = json.dumps(mcp, indent=2) + "\n"
    if platform in ("all", "linux"):
        out[SYSTEMD_UNIT_NAME] = systemd_unit_template(cfg)
    if platform in ("all", "macos"):
        out[LAUNCHD_PLIST_NAME] = launchd_plist_template(cfg)
    out[AUTHZ_ENV_NAME] = authorizer_env_template(cfg)
    return out


_TARGET_FILES = {
    "claude-settings": MANAGED_SETTINGS_NAME,
    "managed-mcp": MANAGED_MCP_NAME,
    "systemd": SYSTEMD_UNIT_NAME,
    "launchd": LAUNCHD_PLIST_NAME,
    "env": AUTHZ_ENV_NAME,
}


def _print_managed_guidance(cfg: dict, artifacts: dict[str, str]) -> None:
    print("\nDeploy (org-managed; outranks user/project/CLI):")
    if MANAGED_SETTINGS_NAME in artifacts:
        print(f"  {MANAGED_SETTINGS_NAME} → one of:")
        for osname, path in MANAGED_SETTINGS_PATHS.items():
            print(f"      {osname:10} {path}")
    if MANAGED_MCP_NAME in artifacts:
        print(f"  {MANAGED_MCP_NAME} → the ClaudeCode dir alongside managed-settings.json")
    print(f"  {AUTHZ_ENV_NAME} → /etc/tenuo/{AUTHZ_ENV_NAME}  (root-owned, chmod 0600)")
    if SYSTEMD_UNIT_NAME in artifacts:
        print(f"  {SYSTEMD_UNIT_NAME} → /etc/systemd/system/  (Linux: Docker; systemctl enable --now tenuo-authorizer)")
    if LAUNCHD_PLIST_NAME in artifacts:
        print(f"  {LAUNCHD_PLIST_NAME} → /Library/LaunchDaemons/  (macOS: NATIVE authorizer; launchctl load)")
    print(f"  also deploy the generated .state/gateway.yaml to {_MANAGED_GATEWAY}/.")
    if LAUNCHD_PLIST_NAME in artifacts:
        print("  macOS runs the authorizer natively, not via Docker: a container Unix socket")
        print("  lives in the Linux VM and the macOS hook cannot reach it.")
    if _template_root(cfg) == _ROOT_PLACEHOLDER:
        print(f"\n!! tenant root unresolved: replace '{_ROOT_PLACEHOLDER}' with the tenant")
        print("   cloud root hex (tenuo-admin / `status` shows the trust anchor) before deploying.")
    if LAUNCHD_PLIST_NAME in artifacts:
        nb = _template_native_bin(cfg)
        if nb == _NATIVE_BIN_PLACEHOLDER:
            print(f"\n!! macOS authorizer path unresolved: pass `--authorizer-bin /path/to/tenuo-authorizer`")
            print(f"   (or set authorizer.binary in tenuo.yaml) so the plist execs a real binary")
            print(f"   instead of '{_NATIVE_BIN_PLACEHOLDER}'.")
        else:
            print(f"\n   macOS authorizer binary: {nb}")
            print("   (confirm this path exists on the target macs; override with --authorizer-bin).")
    print("\nNote: managed enforcement also requires the authorizer to be SYSTEM-pinned")
    print("(the unit/plist above) so a developer cannot run their own permissive one.")


def cmd_managed_template(args) -> None:
    """Generate org-managed (MDM) templates that pin Tenuo governance fleet-wide."""
    cfg = load_config()
    if getattr(args, "bin", None):
        # Pin a uniform fleet-wide launcher path into the hook command.
        os.environ["TENUO_CLAUDE_BIN"] = args.bin
    if getattr(args, "authorizer_bin", None):
        # Bake the native (macOS) authorizer path into the launchd plist so admins
        # don't hand-edit the placeholder.
        _cfg_authorizer(cfg)["binary"] = args.authorizer_bin
    if getattr(args, "socket_group", None):
        _cfg_authorizer(cfg)["socket_group"] = args.socket_group
    platform = getattr(args, "platform", "all") or "all"
    artifacts = _managed_artifacts(cfg, platform)
    target = getattr(args, "target", "all") or "all"
    out = getattr(args, "out", None)

    if target != "all":
        fname = _TARGET_FILES[target]
        if fname not in artifacts:
            if target in ("systemd", "launchd"):
                raise SystemExit(
                    f"{target}: excluded by --platform {platform} "
                    f"(systemd is linux, launchd is macos).")
            raise SystemExit(f"{target}: nothing to generate (no `mcp.downstream` in policy).")
        if not out:
            print(artifacts[fname], end="")
            return
        selected = {fname: artifacts[fname]}
    else:
        selected = artifacts

    out_dir = Path(out or "./tenuo-managed")
    out_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in selected.items():
        (out_dir / fname).write_text(content)
        print(f"wrote {out_dir / fname}")
    _print_managed_guidance(cfg, selected)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

COMMANDS = {
    "init": cmd_init, "refresh": cmd_refresh, "up": cmd_up, "down": cmd_down, "status": cmd_status,
    "disable": cmd_disable, "uninstall": cmd_uninstall,
    "check": cmd_check, "onboard": cmd_onboard, "bootstrap": cmd_bootstrap,
    "install-authorizer": cmd_install_authorizer,
    "pack": cmd_pack,
    "managed-template": cmd_managed_template,
    "audit": cmd_audit, "revoke": cmd_revoke,
    "verify": cmd_verify, "doctor": cmd_doctor, "demo": cmd_demo, "bench": cmd_bench,
    "_hook": cmd_hook, "_managed-hook": cmd_managed_hook,
    "_post": cmd_post, "_mcp-proxy": cmd_mcp_proxy,
    "_managed-mcp-proxy": cmd_managed_mcp_proxy,
}


def main() -> None:
    parser = argparse.ArgumentParser(prog=CLI_COMMAND, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version",
                        version=f"tenuo-claude-code {__version__}")
    sub = parser.add_subparsers(dest="cmd")
    for name in ["down", "status", "check", "revoke",
                 "_hook", "_managed-hook", "_post", "_mcp-proxy", "_managed-mcp-proxy"]:
        sub.add_parser(name)
    sub.add_parser("disable",
                   help="turn governance off (unwire hooks + stop authorizer; keeps policy/state)")
    pun = sub.add_parser("uninstall",
                         help="full teardown: unwire hooks, stop authorizer, delete .state")
    pun.add_argument("--yes", "-y", action="store_true", help="skip the confirmation prompt")
    pun.add_argument("--keep-state", action="store_true",
                     help="keep .state (warrant, keys, gateway, receipts); only unwire + stop")
    pu = sub.add_parser("up", help="start the authorizer (Docker or native binary)")
    pu.add_argument("--native", action="store_true",
                    help="run tenuo-authorizer as a host process (no Docker)")
    pu.add_argument("--docker", action="store_true",
                    help="force Docker container (default when Docker is available)")
    pu.add_argument("--install", action="store_true",
                    help="with --native: install tenuo-authorizer to ~/.tenuo/bin if missing")
    pi_auth = sub.add_parser(
        "install-authorizer",
        help="install the pinned tenuo-authorizer binary to ~/.tenuo/bin",
    )
    pi_auth.add_argument("--force", action="store_true", help="reinstall even if version matches")
    pmt = sub.add_parser(
        "managed-template",
        help="generate org-managed (MDM) templates that pin governance fleet-wide")
    pmt.add_argument("--out", metavar="DIR",
                     help="write all artifacts to DIR (default ./tenuo-managed for `all`)")
    pmt.add_argument("--target",
                     choices=["all", "claude-settings", "managed-mcp", "systemd", "launchd", "env"],
                     default="all",
                     help="emit one artifact to stdout (default: all, written to --out)")
    pmt.add_argument("--bin", metavar="PATH",
                     help="pin a uniform fleet-wide tenuo-claude launcher path in the hook command")
    pmt.add_argument("--platform", choices=["all", "linux", "macos"], default="all",
                     help="which OS service artifact to emit: linux (systemd/Docker), "
                          "macos (launchd/native), or all (default)")
    pmt.add_argument("--authorizer-bin", metavar="PATH",
                     help="native authorizer binary path baked into the macOS launchd plist "
                          "(avoids hand-editing the placeholder)")
    pmt.add_argument("--socket-group", metavar="GROUP",
                     help="harden the managed authorizer socket: chgrp the root-owned socket "
                          "to GROUP and use connect mode 0660")
    pr = sub.add_parser("refresh",
                        help="re-apply tenuo.yaml (warrant, gateway, hooks) after policy edits")
    pr.add_argument("--no-restart", action="store_true",
                    help="skip authorizer restart (gateway stays stale until down/up)")
    pi = sub.add_parser("init", help="compile an existing tenuo.yaml (mint warrant, wire hook + proxy)")
    pi.add_argument("--cloud", action="store_true", help="write tenuo.cloud.yaml (Cloud URL)")
    pi.add_argument("--local", action="store_true", help="move Cloud files aside for local mode")
    pi.add_argument("--scaffold", action="store_true",
                    help="write an example tenuo.yaml if none exists (default: require one)")
    pi.add_argument("--pack", metavar="NAME",
                    help="write a reviewed bundled policy pack first (for example: github-mcp)")
    pi.add_argument("--param", action="append", metavar="NAME=VALUE",
                    help="pack parameter override; repeatable (for example: repos=myorg/service)")
    pi.add_argument("--force", action="store_true",
                    help="with --pack: overwrite an existing tenuo.yaml")
    pi.add_argument("--no-scaffold", action="store_true", help=argparse.SUPPRESS)  # default now; kept for back-compat
    pi.add_argument("--advanced", action="store_true",
                    help="write tenuo.advanced.yaml (human approval overlay; WebFetch example)")
    pi.add_argument("--demo", action="store_true", help=argparse.SUPPRESS)  # deprecated alias
    pi.add_argument("--approver", help="approver identity display name (requires --advanced)")
    pi.add_argument("--approver-id", help="stable approver identity id (requires --advanced)")
    pi.add_argument("--cloud-url", help="control plane URL (with --cloud; default from connect token or api.tenuo.ai)")
    po = sub.add_parser("onboard", help="interactive local or Cloud setup wizard")
    po.add_argument("--local", action="store_true", help="local mode (default when neither flag set)")
    po.add_argument("--cloud", action="store_true", help="Cloud mode")
    po.add_argument("--advanced", action="store_true",
                    help="also write advanced overlay (human approval; with --cloud)")
    po.add_argument("--demo", action="store_true", help=argparse.SUPPRESS)
    po.add_argument("--yes", "-y", action="store_true", help="non-interactive where possible")
    po.add_argument("--connect-token", help="Quick Connect token (Cloud)")
    po.add_argument("--admin-key", help="tenant-admin key for one-time setup (Cloud)")
    po.add_argument("--approver", help="approver display name (requires --advanced)")
    po.add_argument("--approver-id", help="stable approver identity id (requires --advanced)")
    po.add_argument("--no-scaffold", action="store_true",
                    help="fail if tenuo.yaml is missing (default: write an example policy)")
    pb = sub.add_parser("bootstrap", help="check + init + up + verify")
    pb.add_argument("--cloud", action="store_true", help="Cloud quickstart (default: local)")
    pb.add_argument("--advanced", action="store_true", help="include advanced overlay (with --cloud)")
    pb.add_argument("--demo", action="store_true", help=argparse.SUPPRESS)
    pb.add_argument("--yes", "-y", action="store_true")
    pb.add_argument("--no-scaffold", action="store_true",
                    help="fail if tenuo.yaml is missing (default: write an example policy)")
    pb.add_argument("--pack", help="policy pack to use (e.g., filesystem-dev, github-mcp)")
    pb.add_argument("--native", action="store_true",
                    help="use native authorizer backend (skip Docker if available)")
    pb.add_argument("--install", action="store_true", help="auto-install native authorizer if needed")
    pb.add_argument("--connect-token")
    pb.add_argument("--admin-key")
    pb.add_argument("--approver")
    pb.add_argument("--approver-id")
    pp = sub.add_parser("pack", help="list and inspect bundled policy packs")
    pps = pp.add_subparsers(dest="pack_cmd")
    pps.add_parser("list", help="list bundled policy packs")
    ppi = pps.add_parser("inspect", help="show reviewed intent for a pack")
    ppi.add_argument("name")
    pv = sub.add_parser("verify", help="policy self-test against the authorizer")
    pv.add_argument("--deep", action="store_true",
                    help="SSRF matrix, extra Bash denies, live hook exit-code harness")
    pv.add_argument("--no-live", action="store_true",
                    help="with --deep: skip live Claude Code PreToolUse exit-code harness")
    pd = sub.add_parser("doctor", help=argparse.SUPPRESS)
    pd.add_argument("--no-live", action="store_true")
    pdemo = sub.add_parser("demo", help="scripted policy tour (tenuo_demo.py in project, if present)")
    pdemo.add_argument("--advanced", action="store_true",
                       help="include human approval scenarios (WebFetch example; requires overlay in policy)")
    pdemo.add_argument("--live-approval", action="store_true",
                       help="with --advanced: block until approver responds (Cloud)")
    pbench = sub.add_parser("bench", help="measure per-tool-call overhead (authorizer RTT, hook path)")
    pbench.add_argument("--iterations", type=int, default=100,
                        help="timed iterations per scenario (default: 100)")
    pbench.add_argument("--warmup", type=int, default=10, help="warmup iterations (default: 10)")
    pbench.add_argument("--no-hook", action="store_true",
                        help="skip subprocess _hook benchmark (faster)")
    pbench.add_argument("--json", action="store_true", help="machine-readable output")
    pa = sub.add_parser("audit")
    pa.add_argument("--tail", type=int, default=None)
    pa.add_argument("--verify", action="store_true",
                    help="verify receipt signatures, hash chain, and warrant replay")
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return
    # Global install — no governed project directory required.
    if args.cmd != "install-authorizer":
        bind_project_paths(
            sys.modules[__name__],
            fallback_cwd=args.cmd in ("init", "onboard", "bootstrap", "disable", "uninstall", "pack"),
        )
    # Separation of duties: the runtime/agent plane must never carry an admin
    # credential. Admin actions live in `tenuo-admin`. Skip the internal hook
    # handlers — they have their own fail-closed contract and must emit a deny
    # decision rather than raise (a raised SystemExit would be fail-open).
    if args.cmd not in ("_hook", "_managed-hook", "_post", "_mcp-proxy", "_managed-mcp-proxy",
                        "onboard", "bootstrap", "install-authorizer"):
        assert_no_admin_key()
    COMMANDS[args.cmd](args)


if __name__ == "__main__":
    main()
