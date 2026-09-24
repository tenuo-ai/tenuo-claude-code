#!/usr/bin/env python3
"""Claude Code plugin launcher for Tenuo (stdlib only).

The plugin's hooks call this script for every tool call in every project where
the plugin is enabled, so its first job is to stay out of the way. It decides,
per call, whether Tenuo governs the current project and only then hands the
event to the real ``tenuo-claude`` hook.

Decision table for ``pre`` (PreToolUse):

    1. No Tenuo project found (no ``tenuo.yaml`` in the session project dir,
       the hook cwd, or any parent)            -> no output, exit 0 (neutral)
    2. ``TENUO_PROJECT_DIR`` is set but has no ``tenuo.yaml``
                                               -> deny (explicit opt-in is broken)
    3. Project found, but ``.state/`` is missing (policy present, never
       initialized)                            -> no output, exit 0 (neutral)
    4. Project found, ``.state/disabled`` exists (``tenuo-claude disable``)
                                               -> no output, exit 0 (neutral)
    5. Tenuo hooks already wired by ``tenuo-claude init``/``bootstrap`` in
       project, user, or managed settings      -> no output, exit 0 (the wired
                                                  hook enforces; avoids double
                                                  receipts)
    6. Opted in and ``tenuo-claude`` found     -> delegate to ``tenuo-claude _hook``
    7. Opted in but ``tenuo-claude`` missing, crashing, timing out, or printing
       something that is not a hook decision   -> deny (fail closed)

"Opted in" means rows 1 to 5 did not apply: a ``tenuo.yaml`` plus initialized
``.state/`` with no bootstrap wiring and no disable marker.

A deny is the same JSON as the CLI's fail-closed launcher guard
(``_GUARD_DENY_JSON``) with an actionable reason, printed to stdout, the reason
repeated on stderr, and exit code 2 (Claude Code blocks on exit 2 regardless of
JSON parsing).

``post`` (PostToolUse) follows the same routing but never blocks.
``session-start`` prints one status line and never blocks.
``run <args>`` runs ``tenuo-claude <args>`` for the plugin skills.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

POLICY_FILE = "tenuo.yaml"
STATE_DIR = ".state"
DISABLED_MARKER = "disabled"
CLI_NAMES = ("tenuo-claude", "tenuo-claude-code")
PYPI_PACKAGE = "tenuo-claude-code"
BOOTSTRAP_HINT = "tenuo-claude bootstrap --native --pack filesystem-dev"
INSTALL_HINT = f"uv tool install {PYPI_PACKAGE}"

# Claude Code managed settings locations (highest precedence, MDM-pinned).
MANAGED_SETTINGS_PATHS = (
    Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
    Path("/etc/claude-code/managed-settings.json"),
)

# Must stay below the PreToolUse `timeout` in hooks/hooks.json: Claude Code
# lets a timed-out PreToolUse hook through, so the launcher has to give up
# first and deny. 150s approval poll + 30s headroom, same as bootstrap wiring.
PRE_TIMEOUT_DEFAULT = 180.0
POST_TIMEOUT_DEFAULT = 20.0

# Decision labels (returned by `decide`, asserted in tests).
NOOP_NO_PROJECT = "noop:no-project"
NOOP_NOT_INITIALIZED = "noop:not-initialized"
NOOP_DISABLED = "noop:disabled"
NOOP_ALREADY_WIRED = "noop:already-wired"
DELEGATE = "delegate"
DENY_BAD_PROJECT_DIR = "deny:bad-project-dir"
DENY_CLI_MISSING = "deny:cli-missing"


def deny_json(reason: str) -> str:
    """Same shape as the CLI's ``_GUARD_DENY_JSON``, with a specific reason."""
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason}})


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _walk_up(start: Path) -> Path | None:
    try:
        cur = start.expanduser().resolve()
    except (OSError, RuntimeError):
        return None
    for directory in (cur, *cur.parents):
        if (directory / POLICY_FILE).is_file():
            return directory
    return None


def find_project(event: dict, env: dict) -> tuple[Path | None, str | None]:
    """Locate the governed project the same way the CLI does.

    Returns ``(root, error)``. ``TENUO_PROJECT_DIR`` wins, as in the CLI. Then
    the session project dir (stable even after Claude ``cd``s elsewhere, so a
    ``cd /tmp`` can't route around governance), then the hook ``cwd``, then the
    process cwd; each walks up to ``/``.
    """
    explicit = (env.get("TENUO_PROJECT_DIR") or "").strip()
    if explicit:
        root = Path(explicit).expanduser()
        if (root / POLICY_FILE).is_file():
            return root.resolve(), None
        return None, (f"TENUO_PROJECT_DIR={explicit} has no {POLICY_FILE}. "
                      "Fix or unset TENUO_PROJECT_DIR.")
    starts = []
    for raw in (env.get("CLAUDE_PROJECT_DIR"), event.get("cwd"), os.getcwd()):
        if raw and isinstance(raw, str) and raw not in starts:
            starts.append(raw)
    for raw in starts:
        root = _walk_up(Path(raw))
        if root is not None:
            return root, None
    return None, None


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _is_tenuo_command(cmd: str) -> bool:
    """True for a hook command written by ``tenuo-claude init``/``bootstrap``.

    Those commands end in ``_hook`` / ``_managed-hook`` (possibly inside the
    ``/bin/sh -c`` launcher guard) and reference the tenuo CLI or module.
    """
    if "tenuo" not in cmd:
        return False
    for token in cmd.replace("'", " ").replace('"', " ").replace(";", " ").split():
        if token in ("_hook", "_managed-hook"):
            return True
    return False


def settings_have_tenuo_hook(settings) -> bool:
    if not isinstance(settings, dict):
        return False
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    entries = hooks.get("PreToolUse")
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for inner in entry.get("hooks") or []:
            if isinstance(inner, dict) and _is_tenuo_command(str(inner.get("command", ""))):
                return True
    return False


def settings_candidates(root: Path, env: dict) -> list[Path]:
    """Settings files Claude Code actually loaded for this session.

    Project settings come from the session project dir (``CLAUDE_PROJECT_DIR``),
    not from wherever Claude later ``cd``s: wiring in a nested project that the
    session did not start in never runs, so it must not make the plugin stand
    down. Falls back to the discovered root when the variable is absent.
    """
    session = (env.get("CLAUDE_PROJECT_DIR") or "").strip()
    project = Path(session) if session else root
    paths = [project / ".claude" / "settings.json",
             project / ".claude" / "settings.local.json"]
    home = env.get("HOME")
    if home:
        paths.append(Path(home) / ".claude" / "settings.json")
    paths += list(MANAGED_SETTINGS_PATHS)
    return paths


def already_wired(root: Path, env: dict) -> bool:
    return any(settings_have_tenuo_hook(_load_json(p))
               for p in settings_candidates(root, env) if p.is_file())


def _executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def find_cli(root: Path | None, env: dict) -> str | None:
    """Find ``tenuo-claude``: override, project venv, PATH, uv tool, pipx."""
    override = (env.get("TENUO_CLAUDE_BIN") or "").strip()
    if override:
        return override if _executable(Path(override)) else None
    candidates: list[Path] = []
    if root is not None:
        candidates += [root / ".venv" / "bin" / n for n in CLI_NAMES]
    for name in CLI_NAMES:
        found = shutil.which(name, path=env.get("PATH"))
        if found:
            candidates.append(Path(found))
    home = Path(env["HOME"]) if env.get("HOME") else None
    bin_dirs = [env.get(k) for k in ("UV_TOOL_BIN_DIR", "PIPX_BIN_DIR", "XDG_BIN_HOME")]
    if home is not None:
        bin_dirs.append(str(home / ".local" / "bin"))
    for d in bin_dirs:
        if d:
            candidates += [Path(d) / n for n in CLI_NAMES]
    if home is not None:
        candidates += [
            home / ".local" / "share" / "uv" / "tools" / PYPI_PACKAGE / "bin" / CLI_NAMES[0],
            home / ".local" / "pipx" / "venvs" / PYPI_PACKAGE / "bin" / CLI_NAMES[0],
        ]
    for cand in candidates:
        if _executable(cand):
            return str(cand)
    return None


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


def decide(event: dict, env: dict) -> tuple[str, Path | None, str | None, str | None]:
    """Return ``(decision, project_root, cli_path, message)`` for a hook event."""
    root, error = find_project(event, env)
    if error:
        return DENY_BAD_PROJECT_DIR, None, None, error
    if root is None:
        return NOOP_NO_PROJECT, None, None, None
    state = root / STATE_DIR
    if not state.is_dir():
        return NOOP_NOT_INITIALIZED, root, None, None
    if (state / DISABLED_MARKER).exists():
        return NOOP_DISABLED, root, None, None
    if already_wired(root, env):
        return NOOP_ALREADY_WIRED, root, None, None
    cli = find_cli(root, env)
    if cli is None:
        return DENY_CLI_MISSING, root, None, (
            f"{root} is governed by Tenuo but the tenuo-claude CLI was not found "
            "(fail-closed). "
            f"Install it with `{INSTALL_HINT}`, or set TENUO_CLAUDE_BIN, "
            "or run `tenuo-claude disable` to turn governance off here.")
    return DELEGATE, root, cli, None


def _child_env(env: dict, root: Path) -> dict:
    child = dict(env)
    child["TENUO_PROJECT_DIR"] = str(root)
    return child


def _timeout(env: dict, key: str, default: float) -> float:
    try:
        value = float(env.get(key, ""))
        return value if value > 0 else default
    except ValueError:
        return default


def _deny(reason: str) -> int:
    sys.stdout.write(deny_json(reason) + "\n")
    sys.stdout.flush()
    sys.stderr.write(reason + "\n")
    return 2


def run_pre(raw: bytes, env: dict) -> int:
    event = _parse(raw)
    decision, root, cli, message = decide(event, env)
    if decision.startswith("noop"):
        return 0
    if decision != DELEGATE:
        return _deny(f"Tenuo: {message}")
    timeout = _timeout(env, "TENUO_PLUGIN_HOOK_TIMEOUT", PRE_TIMEOUT_DEFAULT)
    try:
        proc = subprocess.run([cli, "_hook"], input=raw, capture_output=True,
                              cwd=str(root), env=_child_env(env, root), timeout=timeout)
    except subprocess.TimeoutExpired:
        return _deny(f"Tenuo: `tenuo-claude _hook` timed out after {timeout:.0f}s (fail-closed). "
                     "Check `tenuo-claude status`.")
    except OSError as exc:
        return _deny(f"Tenuo: could not run {cli} ({exc}) (fail-closed). "
                     f"Reinstall with `{INSTALL_HINT}` or set TENUO_CLAUDE_BIN.")
    out = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode == 2:
        # The hook itself blocked; pass its output through untouched.
        sys.stdout.write(proc.stdout.decode("utf-8", "replace"))
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return 2
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        tail = f": {detail[-1]}" if detail else ""
        return _deny(f"Tenuo: `tenuo-claude _hook` exited {proc.returncode}{tail} (fail-closed). "
                     "Run `tenuo-claude check`.")
    if not out:
        # Observe-only (`mode: dry-run`) deliberately prints nothing so Claude's
        # own permission flow stays in effect.
        return 0
    try:
        parsed = json.loads(out)
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict) or not isinstance(parsed.get("hookSpecificOutput"), dict):
        return _deny("Tenuo: `tenuo-claude _hook` returned an unreadable decision (fail-closed). "
                     "Run `tenuo-claude check`.")
    sys.stdout.write(out + "\n")
    return 0


def run_post(raw: bytes, env: dict) -> int:
    event = _parse(raw)
    decision, root, cli, _ = decide(event, env)
    if decision != DELEGATE:
        return 0
    timeout = _timeout(env, "TENUO_PLUGIN_POST_TIMEOUT", POST_TIMEOUT_DEFAULT)
    try:
        subprocess.run([cli, "_post"], input=raw, capture_output=True, cwd=str(root),
                       env=_child_env(env, root), timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return 0


def status_line(event: dict, env: dict) -> str:
    decision, root, _cli, message = decide(event, env)
    cli_found = find_cli(root, env) is not None
    install = "" if cli_found else f" (install first: {INSTALL_HINT})"
    if decision == NOOP_NO_PROJECT:
        return ("Tenuo not configured here; Claude Code permissions apply as usual. "
                f"To govern this project: {BOOTSTRAP_HINT}{install}")
    if decision == NOOP_NOT_INITIALIZED:
        return (f"Tenuo: {root / POLICY_FILE} found but not initialized, so tool calls are "
                f"NOT governed yet. Run: tenuo-claude bootstrap{install}")
    if decision == NOOP_DISABLED:
        return (f"Tenuo: governance disabled for {root} (tenuo-claude disable). "
                f"Re-enable: tenuo-claude up{install}")
    if decision == NOOP_ALREADY_WIRED:
        return (f"Tenuo: governing {root} via tenuo-claude hooks in Claude settings. "
                "Status: /tenuo:status")
    if decision == DELEGATE:
        return f"Tenuo: governing {root} via the Tenuo plugin. Status: /tenuo:status"
    return f"Tenuo: tool calls will be denied until this is fixed. {message}"


def run_session_start(raw: bytes, env: dict) -> int:
    event = _parse(raw)
    try:
        line = status_line(event, env)
    except Exception as exc:  # never block session start
        line = f"Tenuo: status unavailable ({exc})"
    sys.stdout.write(json.dumps({"systemMessage": line}) + "\n")
    return 0


def run_cli(args: list[str], env: dict) -> int:
    """Run ``tenuo-claude <args>`` in the governed project (for plugin skills)."""
    root, error = find_project({}, env)
    if error:
        print(f"Tenuo: {error}")
        return 1
    cli = find_cli(root, env)
    if cli is None:
        print(f"tenuo-claude not found. Install it with: {INSTALL_HINT}")
        return 1
    if root is None:
        print(f"No {POLICY_FILE} in this directory or any parent. "
              f"To set up Tenuo here: {BOOTSTRAP_HINT}")
        return 1
    print(f"Plugin: {status_line({}, env)}")
    sys.stdout.flush()
    proc = subprocess.run([cli, *args], cwd=str(root), env=_child_env(env, root))
    return proc.returncode


def _parse(raw: bytes) -> dict:
    try:
        event = json.loads(raw.decode("utf-8", "replace") or "{}")
    except ValueError:
        return {}
    return event if isinstance(event, dict) else {}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    mode = argv[0] if argv else ""
    env = dict(os.environ)
    if mode == "run":
        return run_cli(argv[1:], env)
    raw = sys.stdin.buffer.read() if mode in ("pre", "post", "session-start") else b""
    if mode == "pre":
        try:
            return run_pre(raw, env)
        except Exception as exc:  # fail closed only where Tenuo governs
            try:
                decision = decide(_parse(raw), env)[0]
            except Exception:
                decision = NOOP_NO_PROJECT
            if decision.startswith("noop"):
                return 0
            return _deny(f"Tenuo plugin launcher error (fail-closed): {exc}")
    if mode == "post":
        try:
            return run_post(raw, env)
        except Exception:
            return 0
    if mode == "session-start":
        return run_session_start(raw, env)
    sys.stderr.write("usage: tenuo_plugin.py pre|post|session-start|run <args>\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
