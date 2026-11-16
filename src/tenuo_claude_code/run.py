"""Run Claude Code headless under a grant someone else issued.

    tenuo-claude run --warrant W --holder-key K --trusted-root R --workspace DIR -p "task"

The caller (for example Hermes) signs a warrant for this run and hands over the
holder key for it. ``run`` starts ``claude -p`` in DIR with a PreToolUse hook
that checks every tool call against that warrant, in this process's own Python,
against the caller's trusted root. No ``tenuo.yaml``, no authorizer service and
no project state: the grant is the policy.

Claude Code is started so that only our settings apply:

- ``--restricted`` ignores the user, project and local settings files, so a
  repo's own ``.claude/settings.json`` can't disable our hook;
- ``--strict-mcp-config`` with no MCP config: no MCP servers;
- ``--permission-mode dontAsk``: anything our hook doesn't allow is refused, so
  if the hook never ran, tools that need permission are still denied;
- ``--bare`` is never passed (it skips hooks).

When Claude exits, ``run`` prints one JSON object: Claude's result, every allow
and deny, and the head of the hash-chained receipt log.

This module is the generic half of delegation (accept an outside grant, verify
the chain, prove possession, return receipts). Keep it free of the project-mode
state in ``cli.py`` so it can move to the Tenuo SDK when a second agent needs it.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .policy import TOOL_DEFAULTS

# Tools that only touch Claude's own session state (todo lists, planning, asking
# the user). Allowed without a capability. Command-running tools never go here.
HARNESS_TOOLS = frozenset({
    "TodoWrite", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskOutput",
    "AskUserQuestion", "ToolSearch", "EnterPlanMode", "ExitPlanMode",
})
# Subagents: their own tool calls come through this same hook under the same
# warrant, so spawning one widens nothing.
SPAWN_TOOLS = frozenset({"Agent", "Task"})
# Tools whose argument is a path: checked as a resolved absolute path.
PATH_TOOLS = frozenset({"Read", "Write", "Edit", "Glob", "Grep", "NotebookEdit"})
# The tools Claude Code is started with. Anything else isn't even offered.
DEFAULT_TOOLS = ("Read", "Edit", "Write", "Glob", "Grep", "Bash", "TodoWrite")

# Told to Claude up front so it doesn't spend turns discovering the checks.
RULES = (
    "Every tool call in this session is checked against a signed grant before it runs. "
    "File tools work only inside the current working directory. Shell commands: run one "
    "command per call, with no &&, ;, |, redirection, $() or backticks, and no newlines (for "
    "a commit message with a body, pass -m once per paragraph). Only the commands the grant "
    "allows will run; if one is denied, don't try to get around it, say so in your final answer."
)

GRANT_FILE = "grant.json"
RECEIPTS_FILE = "receipts.jsonl"
SETTINGS_FILE = "settings.json"


# ---------------------------------------------------------------------------
# Keys and warrants
# ---------------------------------------------------------------------------


def _key_bytes(text: str) -> bytes:
    """A key given as hex or base64 (standard or URL-safe)."""
    text = text.strip()
    try:
        return bytes.fromhex(text)
    except ValueError:
        pass
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_" if ("-" in text or "_" in text) else None,
                                validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("key is neither hex nor base64") from exc


def public_key(text: str):
    from tenuo import PublicKey
    return PublicKey.from_bytes(_key_bytes(text))


def signing_key(text: str):
    from tenuo import SigningKey
    return SigningKey.from_bytes(_key_bytes(text))


def decode_chain(text: str) -> list:
    """A WarrantStack or a single warrant, as a root-to-leaf list."""
    from tenuo_core import decode_warrant_stack_base64
    text = text.strip()
    try:
        return list(decode_warrant_stack_base64(text))
    except Exception:
        from tenuo import Warrant
        return [Warrant.from_base64(text)]


def _read_secret(value: str) -> str:
    """A value given inline, as @path, as a path to an existing file, or as '-' for stdin."""
    if value == "-":
        return sys.stdin.read().strip()
    path = Path(value[1:] if value.startswith("@") else value).expanduser()
    if value.startswith("@") or (len(value) < 4096 and path.is_file()):
        return path.read_text().strip()
    return value.strip()


# ---------------------------------------------------------------------------
# The decision for one tool call
# ---------------------------------------------------------------------------


def call_args(tool: str, tool_input: dict, workspace: str) -> tuple[str, dict]:
    """(capability, arguments to authorize) for a Claude tool call.

    Raises KeyError for a tool with no capability mapping (denied).
    """
    cap, arg, field = TOOL_DEFAULTS[tool]
    value = (tool_input or {}).get(field)
    if tool in PATH_TOOLS:
        # Glob/Grep default to the working directory; authorize what they touch.
        if not (isinstance(value, str) and value):
            value = workspace
        if not os.path.isabs(value):
            value = os.path.join(workspace, value)
        # Resolve symlinks so a link inside the workspace can't point outside it.
        value = os.path.realpath(value)
    if tool == "WebFetch":
        from urllib.parse import urlsplit
        url = value if isinstance(value, str) else ""
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            host = ""
        return cap, {"url": url, "host": host}
    return cap, {arg: value if value is not None else ""}


def _denial_hint(tool: str, cap: str, reason: str) -> str:
    if tool == "Bash":
        return (f"{reason}. Run one command at a time, without &&, ;, |, $(...) or newlines, "
                "and only the commands this task was granted.")
    if tool in PATH_TOOLS:
        return f"{reason}. Only files inside the granted workspace are allowed."
    return reason


def decide(grant: dict, tool: str, tool_input: dict) -> dict:
    """Check one call. Returns a receipt body with decision and reason."""
    from tenuo import Authorizer

    workspace = grant["workspace"]
    base = {"tool": tool, "ts": int(time.time())}
    if tool in HARNESS_TOOLS:
        return {**base, "decision": "allow", "reason": "session tool"}
    if tool in SPAWN_TOOLS:
        return {**base, "decision": "allow", "reason": "subagent; its calls are checked too"}
    try:
        cap, args = call_args(tool, tool_input, workspace)
    except KeyError:
        return {**base, "decision": "deny", "reason": f"{tool} is not part of this grant"}
    base.update(cap=cap, args=args)
    chain = decode_chain(grant["warrant"])
    leaf = chain[-1]
    holder = signing_key(grant["holder_key"])
    authz = Authorizer(trusted_roots=[public_key(r) for r in grant["trusted_roots"]])
    try:
        pop = leaf.sign(holder, cap, args, int(time.time()))
        authz.check_chain(chain, cap, args, bytes(pop))
    except Exception as exc:
        reason = str(exc) or type(exc).__name__
        return {**base, "decision": "deny", "warrant_id": leaf.id,
                "reason": _denial_hint(tool, cap, reason)}
    return {**base, "decision": "allow", "warrant_id": leaf.id, "reason": "within grant",
            "pop": base64.b64encode(bytes(pop)).decode()}


# ---------------------------------------------------------------------------
# Receipts: append-only, hash-chained
# ---------------------------------------------------------------------------


def _append_receipt(state: Path, body: dict) -> dict:
    import fcntl

    path = state / RECEIPTS_FILE
    with open(path, "a+", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        prev = None
        for line in fh:
            if line.strip():
                prev = json.loads(line)["hash"]
        row = {**body, "prev": prev}
        row["hash"] = hashlib.sha256(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        fh.seek(0, os.SEEK_END)
        fh.write(json.dumps(row, sort_keys=True) + "\n")
        fh.flush()
        fcntl.flock(fh, fcntl.LOCK_UN)
    return row


def read_receipts(state: Path) -> tuple[list[dict], bool]:
    """All receipts and whether the hash chain is intact."""
    path = state / RECEIPTS_FILE
    if not path.exists():
        return [], True
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    prev = None
    for row in rows:
        body = {k: v for k, v in row.items() if k != "hash"}
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if row.get("prev") != prev or row.get("hash") != digest:
            return rows, False
        prev = row["hash"]
    return rows, True


# ---------------------------------------------------------------------------
# The hook (called by Claude Code for every tool call)
# ---------------------------------------------------------------------------


def hook(state: Path) -> None:
    """PreToolUse hook. Always prints a decision; any error is a deny."""
    decision, reason, tool = "deny", "Tenuo hook error (denied)", ""
    try:
        grant = json.loads((state / GRANT_FILE).read_text())
        try:
            event = json.loads(sys.stdin.read() or "{}")
        except json.JSONDecodeError:
            event = {}
        tool = str(event.get("tool_name") or "")
        body = decide(grant, tool, event.get("tool_input") or {})
        if event.get("agent_type"):
            body["agent_type"] = event["agent_type"]
        _append_receipt(state, body)
        decision = body["decision"]
        reason = (f"Tenuo allowed {tool}" if decision == "allow"
                  else f"Tenuo denied {tool}: {body['reason']}")
    except BaseException as exc:  # noqa: BLE001 - fail closed on anything
        reason = f"Tenuo hook error (denied): {type(exc).__name__}: {exc}"
        try:
            _append_receipt(state, {"tool": tool, "ts": int(time.time()), "decision": "deny",
                                    "reason": reason})
        except BaseException:
            pass
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": decision,
        "permissionDecisionReason": reason}}))


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _hook_command(state: Path) -> str:
    import shlex
    return shlex.join([sys.executable, "-I", "-m", "tenuo_claude_code.run", "_hook",
                       "--state", str(state)])


def prepare(state: Path, *, warrant: str, holder_key: str, trusted_roots: list[str],
            workspace: Path) -> dict:
    """Verify the grant and write the run's state. Raises ValueError when unusable."""
    from tenuo import Authorizer

    if not trusted_roots:
        raise ValueError("at least one --trusted-root is required")
    chain = decode_chain(warrant)
    holder = signing_key(holder_key)
    leaf = chain[-1]
    if leaf.authorized_holder.to_bytes() != holder.public_key.to_bytes():
        raise ValueError("the holder key does not match the warrant's holder")
    authz = Authorizer(trusted_roots=[public_key(r) for r in trusted_roots])
    authz.verify_chain(chain)  # trusted root, linkage, narrowing, expiry, signatures
    if leaf.is_expired():
        raise ValueError("the warrant has expired")
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    grant = {"warrant": warrant.strip(), "holder_key": holder_key.strip(),
             "trusted_roots": [r.strip() for r in trusted_roots],
             "workspace": os.path.realpath(workspace)}
    fd = os.open(state / GRANT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(grant, fh)
    settings = {
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": _hook_command(state), "timeout": 30}]}]},
        # Belt and braces: never offer the tools that skip hooks or go outside.
        "permissions": {"defaultMode": "dontAsk"},
    }
    (state / SETTINGS_FILE).write_text(json.dumps(settings, indent=2))
    return {"warrant_id": leaf.id, "expires_at": str(leaf.expires_at()),
            "capabilities": sorted(leaf.tools)}


def claude_argv(claude: str, state: Path, prompt: str, *, tools: list[str],
                model: str | None, max_turns: int | None, extra: list[str]) -> list[str]:
    if "--bare" in extra or any(a.startswith("--dangerously") for a in extra):
        raise ValueError("--bare and --dangerously-* skip Tenuo's checks and are refused")
    argv = [claude, "-p", prompt, "--output-format", "json",
            "--restricted", "--tools", ",".join(tools),
            "--settings", str(state / SETTINGS_FILE), "--strict-mcp-config",
            "--permission-mode", "dontAsk", "--permission-prompts", "none"]
    argv += ["--append-system-prompt", RULES]
    if model:
        argv += ["--model", model]
    if max_turns:
        argv += ["--max-turns", str(max_turns)]
    return argv + extra


def summarize(state: Path, prepared: dict, proc: subprocess.CompletedProcess | None,
              *, timed_out: bool = False, error: str | None = None) -> dict:
    rows, chain_ok = read_receipts(state)
    allowed = [r for r in rows if r.get("decision") == "allow"]
    denied = [r for r in rows if r.get("decision") == "deny"]
    result_text, cost, claude_error = None, None, None
    if proc is not None:
        try:
            out = json.loads(proc.stdout or "{}")
            result_text = out.get("result")
            cost = out.get("total_cost_usd")
            if out.get("is_error"):
                claude_error = out.get("subtype") or "error"
        except json.JSONDecodeError:
            result_text = (proc.stdout or "").strip()[-4000:] or None
        if proc.returncode and not claude_error:
            claude_error = (proc.stderr or "").strip()[-1000:] or f"exit {proc.returncode}"
    return {
        "ok": error is None and not timed_out and proc is not None and proc.returncode == 0,
        "error": error or ("timed out" if timed_out else claude_error),
        "result": result_text,
        "cost_usd": cost,
        "grant": prepared,
        "allowed": len(allowed),
        "denied": [{"tool": r.get("tool"), "args": r.get("args"), "reason": r.get("reason")}
                   for r in denied],
        "tools_used": sorted({r.get("tool") for r in allowed if r.get("tool")}),
        "receipts": {"file": str(state / RECEIPTS_FILE), "count": len(rows),
                     "head": rows[-1]["hash"] if rows else None, "chain_ok": chain_ok},
    }


def cmd_run(args) -> int:
    workspace = Path(args.workspace).expanduser()
    if not workspace.is_dir():
        print(json.dumps({"ok": False, "error": f"workspace {workspace} is not a directory"}))
        return 2
    state = Path(args.state).expanduser() if args.state else Path(
        tempfile.mkdtemp(prefix="tenuo-claude-run-"))
    prompt = args.prompt if args.prompt != "-" else sys.stdin.read()
    try:
        prepared = prepare(state, warrant=_read_secret(args.warrant),
                           holder_key=_read_secret(args.holder_key),
                           trusted_roots=[_read_secret(r) for r in args.trusted_root],
                           workspace=workspace)
        claude = args.claude or os.environ.get("TENUO_CLAUDE_BIN") or shutil.which("claude")
        if not claude:
            raise ValueError("claude is not installed (or set --claude / TENUO_CLAUDE_BIN)")
        argv = claude_argv(claude, state, prompt, tools=args.tools.split(","),
                           model=args.model, max_turns=args.max_turns, extra=args.claude_args)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"grant refused: {exc}"}))
        return 2
    env = {k: v for k, v in os.environ.items() if not k.startswith("TENUO_")}
    try:
        proc = subprocess.run(argv, cwd=os.path.realpath(workspace), env=env,
                              capture_output=True, text=True, timeout=args.timeout,
                              stdin=subprocess.DEVNULL)
        summary = summarize(state, prepared, proc)
    except subprocess.TimeoutExpired:
        summary = summarize(state, prepared, None, timed_out=True)
    print(json.dumps(summary, indent=2 if args.pretty else None))
    return 0 if summary["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tenuo-claude run", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--warrant", required=True,
                   help="warrant or warrant stack (base64): inline, @file, a file path, or -")
    p.add_argument("--holder-key", required=True,
                   help="signing key the warrant is held by (hex or base64; inline or @file)")
    p.add_argument("--trusted-root", action="append", default=[], required=True,
                   help="issuer public key to trust (hex or base64); repeatable")
    p.add_argument("--workspace", required=True, help="directory Claude Code runs in")
    p.add_argument("-p", "--prompt", required=True, help="the task, or - for stdin")
    p.add_argument("--state", help="directory for this run's grant and receipts (default: new temp dir)")
    p.add_argument("--tools", default=",".join(DEFAULT_TOOLS),
                   help="Claude Code tools to offer (default: %(default)s)")
    p.add_argument("--model")
    p.add_argument("--max-turns", type=int)
    p.add_argument("--timeout", type=int, default=1800, help="seconds (default: %(default)s)")
    p.add_argument("--claude", help="path to the claude binary")
    p.add_argument("--pretty", action="store_true")
    p.add_argument("claude_args", nargs="*", help="extra arguments for claude, after --")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["_hook"]:
        hp = argparse.ArgumentParser(prog="tenuo-claude run _hook")
        hp.add_argument("--state", required=True)
        hook(Path(hp.parse_args(argv[1:]).state))
        return 0
    return cmd_run(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
