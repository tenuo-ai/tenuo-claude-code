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
    3. Project found, but this user has not set it up on this machine: there is
       no state directory with ``state.json`` outside the project. A ``.state``
       folder inside the project does not count, whoever put it there
                                               -> no output, exit 0 (neutral)
    4. Set up, and the state directory's ``disabled`` marker exists
       (``tenuo-claude disable``)              -> no output, exit 0 (neutral)
    5. Tenuo hooks already wired by ``tenuo-claude init``/``bootstrap`` in
       project, user, or managed settings      -> no output, exit 0 (the wired
                                                  hook enforces; avoids double
                                                  receipts)
    6. Opted in and ``tenuo-claude`` found     -> delegate to ``tenuo-claude _hook``
    7. Opted in but ``tenuo-claude`` missing, crashing, timing out, or printing
       something that is not a hook decision   -> deny (fail closed)

"Opted in" means rows 1 to 5 did not apply: a ``tenuo.yaml``, set up by this
user, with no bootstrap wiring and no disable marker.

Which ``tenuo-claude`` runs: the user's own (the override, ``PATH``, the uv and
pipx locations) comes first. A copy inside the project is used only when there
is no other and the user has set the project up; before that it is never run.
Paths are made absolute first, and "inside the project" is judged both by where
a file sits and by what it points to.

A deny is the same JSON as the CLI's fail-closed launcher guard
(``_GUARD_DENY_JSON``) with an actionable reason, printed to stdout, the reason
repeated on stderr, and exit code 2 (Claude Code blocks on exit 2 regardless of
JSON parsing).

``post`` (PostToolUse) follows the same routing but never blocks.
``session-start`` prints one status line and never blocks. In a project with
no Tenuo policy it prints the setup hint once per machine, then stays silent.
``run <command>`` runs a read-only ``tenuo-claude`` command for the plugin
skills (see ``SKILL_COMMANDS``); anything that changes state is refused, because
the skills pre-approve this script and a pre-approved command must not be able
to install, rewire or switch governance off. It always exits 0 and reports a
failure in its output: Claude Code drops a skill whose injected command exits
non-zero, which would hide the skill's own guidance in exactly the cases it is
written for (no CLI, no policy, a failed check).
"""

from __future__ import annotations

import hashlib
import json
import re
import os
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
SETUP_HINT = "/tenuo:setup"
# The only commands `run` passes to the CLI. All of them read; none writes
# policy, wiring or state, starts or stops the authorizer, or installs anything.
# `verify` and `check` are not among them: the self-test writes probe files
# into the project, and the preflight runs the project's launcher script when
# one exists.
SKILL_COMMANDS = ("status", "audit", "state-dir", "--version")
# Flags `run` lets through, per command.
SKILL_FLAGS = {"audit": ("--verify", "--tail")}
HINT_MARKER = "setup-hint-shown"
CLOUD_FILES = ("cloud.env", "cloud_state.json")
# Policy overlays that only a Cloud setup writes. Local bootstrap moves them aside.
CLOUD_OVERLAYS = ("tenuo.cloud.yaml", "tenuo.advanced.yaml")

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
NOOP_STATE_IN_PROJECT = "noop:state-in-project"
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
        # Only universal wiring is sufficient to stand down for every event.
        # Partial matchers may cover Read while leaving Bash/MCP unguarded.
        if entry.get("matcher", "*") not in ("", "*"):
            continue
        for inner in entry.get("hooks") or []:
            if isinstance(inner, dict) and inner.get("type") == "command" and _is_tenuo_command(str(inner.get("command", ""))):
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


def find_cli(root: Path | None, env: dict, skip=None) -> str | None:
    """Find ``tenuo-claude``: override, project venv, PATH, uv tool, pipx.

    ``skip`` is an optional test for candidates that must not be used, wherever
    they were found (the override and ``PATH`` included).

    Always returns an absolute path. The CLI is started with the project as its
    working directory, so a relative path would be checked against one
    directory here and then run from another.
    """
    def absolute(value) -> Path:
        return Path(os.path.abspath(os.path.expanduser(str(value))))

    override = (env.get("TENUO_CLAUDE_BIN") or "").strip()
    if override:
        pinned = absolute(override)
        usable = _executable(pinned) and not (skip and skip(pinned))
        return str(pinned) if usable else None
    candidates: list[Path] = []
    if root is not None:
        candidates += [root / ".venv" / "bin" / n for n in CLI_NAMES]
    # Every PATH entry, not only the first match: when the first match is one
    # the caller skips, the search has to go on to the next directory.
    path_dirs = [d for d in (env.get("PATH") or os.defpath).split(os.pathsep) if d]
    for name in CLI_NAMES:
        candidates += [Path(d) / name for d in path_dirs]
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
    for cand in map(absolute, candidates):
        if skip is not None and skip(cand):
            continue
        if _executable(cand):
            return str(cand)
    return None


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


def project_state_dir(root: Path, env: dict) -> Path:
    """Stdlib-only equivalent of the CLI resolver; usable without its install."""
    override = (env.get("TENUO_STATE_DIR") or "").strip()
    home = Path(env.get("HOME") or str(Path.home()))
    if override:
        if override == "~" or override.startswith("~/"):
            override = str(home) + override[1:]
        return Path(override).resolve()
    root = root.resolve()
    name = root.name.strip().lower().replace("_", "-").replace(" ", "-")
    name = re.sub(r"-+", "-", re.sub(r"[^a-z0-9-]+", "-", name)).strip("-")
    name = name[:64] if name else "tenuo-claude"
    digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:12]
    state = home / ".tenuo" / "projects" / f"{name}-{digest}"
    legacy = root / STATE_DIR
    if not state.is_dir() and (legacy / "state.json").is_file():
        return legacy
    return state


def _inside(path: Path, root: Path) -> bool:
    """True when ``path`` belongs to ``root``, by where it sits or by what it
    points to. A link inside the project to a file outside it is still the
    project's, and so is a link outside it to a file inside it."""
    def spellings(value) -> set[str]:
        raw = os.path.expanduser(str(value))
        return {os.path.abspath(raw).casefold(), os.path.realpath(raw).casefold()}

    for base in spellings(root):
        base = base.rstrip(os.sep)
        for candidate in spellings(path):
            if candidate == base or candidate.startswith(base + os.sep):
                return True
    return False


def user_state_dir(root: Path, env: dict) -> Path | None:
    """The project's state directory, when this user set the project up here.

    The evidence is ``state.json`` in a state directory outside the project,
    which ``tenuo-claude init`` writes and a repository cannot ship. An
    in-project ``.state``, or a link from the project to somewhere else, does
    not count. Returns None otherwise.
    """
    override = (env.get("TENUO_STATE_DIR") or "").strip()
    state = Path(os.path.expanduser(override)) if override else project_state_dir(root, env)
    if (state / "state.json").is_file() and not _inside(state, root):
        return state
    return None


def _set_up_by_this_user(root: Path, env: dict) -> bool:
    return user_state_dir(root, env) is not None


def _project_carries_state(root: Path, env: dict) -> bool:
    """True when the project has a state folder of its own (older layout, a
    ``TENUO_STATE_DIR`` pointing into it, or files a repository shipped)."""
    override = (env.get("TENUO_STATE_DIR") or "").strip()
    if override and _inside(Path(os.path.expanduser(override)), root):
        return os.path.isdir(os.path.expanduser(override))
    return (root / STATE_DIR).exists() or (root / STATE_DIR).is_symlink()


def resolve_cli(root: Path | None, env: dict) -> tuple[str | None, str | None]:
    """Pick the ``tenuo-claude`` to run. Returns ``(cli, unused_project_copy)``.

    The user's own CLI wins. A copy inside the project is the fallback, and
    only in a project this user has set up; otherwise it is returned as the
    second value, to be named but not run.
    """
    if root is None:
        return find_cli(None, env), None
    mine = find_cli(None, env, skip=lambda candidate: _inside(candidate, root))
    if mine is not None:
        return mine, None
    local = find_cli(root, env)
    if local is None:
        return None, None
    if not _inside(Path(local), root) or _set_up_by_this_user(root, env):
        return local, None
    return None, local


def decide(event: dict, env: dict) -> tuple[str, Path | None, str | None, str | None]:
    """Return ``(decision, project_root, cli_path, message)`` for a hook event."""
    root, error = find_project(event, env)
    if error:
        return DENY_BAD_PROJECT_DIR, None, None, error
    if root is None:
        return NOOP_NO_PROJECT, None, None, None
    state = user_state_dir(root, env)
    if state is None:
        # Not set up by this user on this machine, so the plugin runs nothing
        # for this project. Hooks the CLI wired into Claude's settings are
        # Claude Code's to run, and still do the enforcing where they exist.
        if already_wired(root, env):
            return NOOP_ALREADY_WIRED, root, None, None
        if _project_carries_state(root, env):
            return NOOP_STATE_IN_PROJECT, root, None, None
        return NOOP_NOT_INITIALIZED, root, None, None
    if (state / DISABLED_MARKER).exists():
        return NOOP_DISABLED, root, None, None
    if already_wired(root, env):
        return NOOP_ALREADY_WIRED, root, None, None
    cli, _unused = resolve_cli(root, env)
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
    cli_found = resolve_cli(root, env)[0] is not None
    install = "" if cli_found else f" (install first: {INSTALL_HINT})"
    if decision == NOOP_NO_PROJECT:
        return ("Tenuo not configured here; Claude Code permissions apply as usual. "
                f"To govern this project: {SETUP_HINT}")
    if decision == NOOP_NOT_INITIALIZED:
        return (f"Tenuo: {root / POLICY_FILE} found but not initialized, so tool calls are "
                f"NOT governed yet. Run: tenuo-claude bootstrap{install}")
    if decision == NOOP_STATE_IN_PROJECT:
        return (f"Tenuo: {root} keeps a Tenuo state folder inside the project, which the plugin "
                "does not act on, so tool calls are NOT governed by the plugin here. If you set "
                "this project up with an older version, run `tenuo-claude refresh` from your "
                f"own terminal; otherwise set it up with {SETUP_HINT}{install}")
    if decision == NOOP_DISABLED:
        return (f"Tenuo: governance disabled for {root} (tenuo-claude disable). "
                f"Re-enable: tenuo-claude up{install}")
    if decision == NOOP_ALREADY_WIRED:
        return (f"Tenuo: governing {root} via tenuo-claude hooks in Claude settings. "
                "Status: /tenuo:status")
    if decision == DELEGATE:
        return f"Tenuo: governing {root} via the Tenuo plugin. Status: /tenuo:status"
    return f"Tenuo: tool calls will be denied until this is fixed. {message}"


def _hint_already_shown(env: dict) -> bool:
    """True when the "not configured here" hint was shown before on this machine.

    The marker lives in the plugin's own data directory. Without one (an older
    Claude Code), the hint is shown every time, as before.
    """
    data = (env.get("CLAUDE_PLUGIN_DATA") or "").strip()
    if not data:
        return False
    marker = Path(data) / HINT_MARKER
    if marker.exists():
        return True
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("shown\n", encoding="utf-8")
    except OSError:
        pass
    return False


def run_session_start(raw: bytes, env: dict) -> int:
    event = _parse(raw)
    try:
        # Stay out of the way in projects that never asked for Tenuo: say how to
        # set it up once, then nothing.
        if decide(event, env)[0] == NOOP_NO_PROJECT and _hint_already_shown(env):
            return 0
        line = status_line(event, env)
    except Exception as exc:  # never block session start
        line = f"Tenuo: status unavailable ({exc})"
    sys.stdout.write(json.dumps({"systemMessage": line}) + "\n")
    return 0


def run_cli(args: list[str], env: dict) -> int:
    """Run ``tenuo-claude <args>`` in the governed project (for plugin skills).

    Always returns 0. A skill's injected command that exits non-zero aborts the
    whole skill, so the outcome is reported in the output instead.

    The output keeps three cases apart, because they mean different things for
    the user: no policy anywhere (Tenuo is not set up here), a project that
    exists but could not be inspected (the ``Plugin:`` line still says whether
    calls are governed or denied), and a CLI run that failed (a final
    ``[tenuo-claude exited N]`` line).
    """
    command = args[0] if args else ""
    extras = [a for a in args[1:] if not a.isdigit()]
    if command not in SKILL_COMMANDS or any(a not in SKILL_FLAGS.get(command, ()) for a in extras):
        print(f"Tenuo: the plugin runs these read-only commands only: {', '.join(SKILL_COMMANDS)} "
              f"(audit also takes --verify and --tail N). Run `tenuo-claude {' '.join(args)}` yourself.")
        return 0
    root, error = find_project({}, env)
    if error:
        # Broken explicit opt-in: the hooks deny every call until it is fixed.
        print(f"Plugin: {status_line({}, env)}")
        return 0
    here = Path(env.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    if root is None:
        # No policy yet, so nothing is run; only say where a CLI is. One in the
        # project's own virtualenv is worth naming, or setup installs a second.
        cli = find_cli(here, env)
        cli_note = f"found at {cli}" if cli else f"not installed (install: {INSTALL_HINT})"
        print(f"No {POLICY_FILE} in this directory or any parent: Tenuo is not set up here. "
              f"To set it up: {SETUP_HINT}. tenuo-claude CLI: {cli_note}.")
        print(f"Project: {here}")
        credentials = any((d / name).exists()
                          for d in (project_state_dir(here, env), here / STATE_DIR)
                          for name in CLOUD_FILES)
        overlays = [name for name in CLOUD_OVERLAYS if (here / name).exists()]
        if credentials or overlays:
            found = " and ".join(part for part in (
                "Cloud credentials" if credentials else "",
                ", ".join(overlays) if overlays else "") if part)
            print(f"Found {found} for this directory but no {POLICY_FILE}: an unfinished "
                  "Cloud setup. Do not bootstrap it in local mode.")
        return 0
    print(f"Plugin: {status_line({}, env)}")
    print(f"Project: {root}")
    cli, project_copy = resolve_cli(root, env)
    if cli is None and project_copy is not None:
        print(f"The only tenuo-claude found is inside this project ({project_copy}). The plugin "
              "does not run a project's own copy before the project is set up on this "
              f"machine. Run `{project_copy} {' '.join(args)}` yourself, or {SETUP_HINT}.")
        return 0
    if cli is None:
        # The project exists; only the inspection is unavailable. Governance
        # state is whatever the Plugin line above says.
        print(f"tenuo-claude not found, so `tenuo-claude {' '.join(args)}` could not run. "
              f"Install it with: {INSTALL_HINT}")
        return 0
    print(f"CLI: {cli}")
    sys.stdout.flush()
    try:
        proc = subprocess.run([cli, *args], cwd=str(root), env=_child_env(env, root))
    except OSError as exc:
        print(f"Tenuo: could not run {cli} ({exc})")
        return 0
    if proc.returncode != 0:
        sys.stdout.flush()
        print(f"[tenuo-claude exited {proc.returncode}]")
    return 0


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
