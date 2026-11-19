"""Decision table for the Claude Code plugin launcher (plugins/tenuo/scripts).

The plugin's hooks run in EVERY project where the plugin is enabled, so the
launcher must be neutral (exit 0, no output) unless the project opted in, must
stand down when bootstrap-written hooks already enforce, and must fail closed
(deny) when an opted-in project can't reach the real `tenuo-claude _hook`.

Two layers: `decide()` unit tests for routing, and end-to-end runs of the
`tenuo-hook` sh entry point with fake `tenuo-claude` binaries, which is exactly
what Claude Code executes.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

from tenuo_claude_code import cli

REPO = Path(__file__).resolve().parents[1]
PLUGIN = REPO / "plugins" / "tenuo"
SCRIPTS = PLUGIN / "scripts"
HOOK_SH = SCRIPTS / "tenuo-hook"

_spec = importlib.util.spec_from_file_location("tenuo_plugin", SCRIPTS / "tenuo_plugin.py")
tp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tp)

PRE_EVENT = {"hook_event_name": "PreToolUse", "tool_name": "Read",
             "tool_input": {"file_path": "/etc/passwd"}}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


@pytest.fixture
def env(home, tmp_path, monkeypatch):
    """Isolated environment: fake HOME, PATH without any tenuo-claude."""
    monkeypatch.setattr(tp, "MANAGED_SETTINGS_PATHS", ())
    empty_bin = tmp_path / "emptybin"
    empty_bin.mkdir()
    return {"HOME": str(home), "PATH": f"{empty_bin}:/usr/bin:/bin"}


def state_dir(root: Path, home: Path | None = None) -> Path:
    """Where this user's state for ``root`` lives: under their home, as the CLI
    puts it. Tests keep the fake home beside the project unless told otherwise."""
    home = home or root.parent / "home"
    return tp.project_state_dir(root, {"HOME": str(home)})


def make_project(root: Path, *, state=True, disabled=False, home: Path | None = None,
                 in_project_state=False) -> Path:
    """A project with a policy. ``state`` sets it up for this user (state.json
    under their home). ``in_project_state`` instead puts the state folder inside
    the project, which is what an older layout or a cloned repository has."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "tenuo.yaml").write_text("name: test\n")
    where = root / ".state" if in_project_state else state_dir(root, home)
    if state:
        where.mkdir(parents=True, exist_ok=True)
        (where / "state.json").write_text("{}")
    if disabled:
        (where / "disabled").write_text("disabled\n")
    return root


def fake_cli(path: Path, body: str) -> Path:
    """Write an executable fake `tenuo-claude` (POSIX sh)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def wire_like_bootstrap(monkeypatch, project: Path, home: Path | None = None) -> None:
    """Write .claude/settings.json with the REAL bootstrap wiring code."""
    monkeypatch.setattr(cli, "DEMO_DIR", project, raising=False)
    monkeypatch.setattr(cli, "STATE", state_dir(project, home), raising=False)
    monkeypatch.setattr(cli, "APPROVAL_POLL_SECONDS", 30, raising=False)
    monkeypatch.setattr(cli, "LAUNCHER", project / "bin" / "tenuo-claude", raising=False)
    monkeypatch.setattr(cli, "LAUNCHER_REL", "./bin/tenuo-claude", raising=False)
    cli.write_claude_wiring({"name": "test", "approval": {}})


def run_hook(mode: str, event: dict, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    full_env = {"TENUO_PLUGIN_PYTHON": sys.executable, **env}
    return subprocess.run([str(HOOK_SH), mode], input=json.dumps(event).encode(),
                          capture_output=True, cwd=str(cwd), env=full_env, timeout=60)


def assert_deny(proc, needle: str) -> dict:
    assert proc.returncode == 2, proc
    out = json.loads(proc.stdout)
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert needle in hso["permissionDecisionReason"]
    return out


# ---------------------------------------------------------------------------
# decide(): the routing table
# ---------------------------------------------------------------------------


def test_no_project_is_neutral(tmp_path, env):
    elsewhere = tmp_path / "unrelated"
    elsewhere.mkdir()
    decision, root, cli_path, _ = tp.decide({"cwd": str(elsewhere)}, {**env, "CLAUDE_PROJECT_DIR": str(elsewhere)})
    assert decision == tp.NOOP_NO_PROJECT
    assert root is None and cli_path is None


def test_tenuo_project_dir_without_policy_denies(tmp_path, env):
    bad = tmp_path / "bad"
    bad.mkdir()
    decision, *_ , msg = tp.decide({}, {**env, "TENUO_PROJECT_DIR": str(bad)})
    assert decision == tp.DENY_BAD_PROJECT_DIR
    assert "TENUO_PROJECT_DIR" in msg


def test_policy_without_state_is_not_initialized(tmp_path, env):
    proj = make_project(tmp_path / "p", state=False)
    decision, root, *_ = tp.decide({"cwd": str(proj)}, env)
    assert decision == tp.NOOP_NOT_INITIALIZED
    assert root == proj.resolve()


def test_disabled_marker_is_neutral(tmp_path, env):
    proj = make_project(tmp_path / "p", disabled=True)
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "exit 0")
    assert tp.decide({"cwd": str(proj)}, env)[0] == tp.NOOP_DISABLED


def test_bootstrap_wiring_in_project_settings_stands_down(tmp_path, env, monkeypatch):
    proj = make_project(tmp_path / "p")
    wire_like_bootstrap(monkeypatch, proj)
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "exit 0")
    assert tp.decide({"cwd": str(proj)}, {**env, "CLAUDE_PROJECT_DIR": str(proj)})[0] == tp.NOOP_ALREADY_WIRED


def test_bootstrap_wiring_detected_in_local_user_and_managed_settings(tmp_path, env, home, monkeypatch):
    proj = make_project(tmp_path / "p")
    wire_like_bootstrap(monkeypatch, proj)
    wired = (proj / ".claude" / "settings.json").read_text()
    (proj / ".claude" / "settings.json").unlink()
    ev, e = {"cwd": str(proj)}, {**env, "CLAUDE_PROJECT_DIR": str(proj)}

    (proj / ".claude" / "settings.local.json").write_text(wired)
    assert tp.decide(ev, e)[0] == tp.NOOP_ALREADY_WIRED
    (proj / ".claude" / "settings.local.json").unlink()

    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text(wired)
    assert tp.decide(ev, e)[0] == tp.NOOP_ALREADY_WIRED
    (home / ".claude" / "settings.json").unlink()

    managed = tmp_path / "managed-settings.json"
    managed.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command", "command": "/opt/tenuo/bin/tenuo-claude _managed-hook"}]}]}}))
    monkeypatch.setattr(tp, "MANAGED_SETTINGS_PATHS", (managed,))
    assert tp.decide(ev, e)[0] == tp.NOOP_ALREADY_WIRED


def test_unrelated_hooks_do_not_count_as_wiring(tmp_path, env):
    proj = make_project(tmp_path / "p")
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo _hook"}]},
        {"matcher": "*", "hooks": [{"type": "command", "command": "tenuo-lint --fix"}]}]}}))
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "exit 0")
    assert tp.decide({"cwd": str(proj)}, env)[0] == tp.DELEGATE


def test_wiring_in_a_nested_project_the_session_did_not_load_is_ignored(tmp_path, env, monkeypatch):
    """Claude only loads settings from the session project dir. Wiring inside a
    nested project it later `cd`s into never runs, so the plugin must enforce."""
    outer = tmp_path / "outer"
    outer.mkdir()
    inner = make_project(outer / "inner", home=tmp_path / "home")
    wire_like_bootstrap(monkeypatch, inner, tmp_path / "home")
    fake_cli(inner / ".venv" / "bin" / "tenuo-claude", "exit 0")
    decision = tp.decide({"cwd": str(inner)}, {**env, "CLAUDE_PROJECT_DIR": str(outer)})[0]
    assert decision == tp.DELEGATE


def test_opted_in_with_cli_delegates(tmp_path, env):
    proj = make_project(tmp_path / "p")
    fake = fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "exit 0")
    decision, root, cli_path, _ = tp.decide({"cwd": str(proj)}, env)
    assert decision == tp.DELEGATE
    assert root == proj.resolve() and cli_path == str(fake)


def test_opted_in_without_cli_denies(tmp_path, env):
    proj = make_project(tmp_path / "p")
    decision, *_, msg = tp.decide({"cwd": str(proj)}, env)
    assert decision == tp.DENY_CLI_MISSING
    assert "uv tool install tenuo-claude-code" in msg


def test_walks_up_from_subdirectory(tmp_path, env):
    proj = make_project(tmp_path / "p")
    sub = proj / "src" / "pkg"
    sub.mkdir(parents=True)
    assert tp.decide({"cwd": str(sub)}, env)[0] == tp.DENY_CLI_MISSING


def test_cd_out_of_project_does_not_escape_governance(tmp_path, env):
    """The session project dir is checked even after Claude `cd`s to /tmp."""
    proj = make_project(tmp_path / "p")
    outside = tmp_path / "outside"
    outside.mkdir()
    decision, root, *_ = tp.decide({"cwd": str(outside)}, {**env, "CLAUDE_PROJECT_DIR": str(proj)})
    assert decision == tp.DENY_CLI_MISSING and root == proj.resolve()


@pytest.mark.parametrize("where", ["path", "uv_tool", "pipx_venv", "override"])
def test_cli_discovery_locations(tmp_path, env, home, where):
    proj = make_project(tmp_path / "p")
    e = dict(env)
    if where == "path":
        fake = fake_cli(tmp_path / "pathbin" / "tenuo-claude", "exit 0")
        e["PATH"] = f"{fake.parent}:{e['PATH']}"
    elif where == "uv_tool":
        fake = fake_cli(home / ".local" / "bin" / "tenuo-claude", "exit 0")
    elif where == "pipx_venv":
        fake = fake_cli(home / ".local" / "pipx" / "venvs" / "tenuo-claude-code" / "bin" / "tenuo-claude", "exit 0")
    else:
        fake = fake_cli(tmp_path / "custom" / "tc", "exit 0")
        e["TENUO_CLAUDE_BIN"] = str(fake)
    decision, _, cli_path, _ = tp.decide({"cwd": str(proj)}, e)
    assert decision == tp.DELEGATE and cli_path == str(fake)


def test_broken_override_is_not_silently_replaced(tmp_path, env, home):
    proj = make_project(tmp_path / "p")
    fake_cli(home / ".local" / "bin" / "tenuo-claude", "exit 0")
    e = {**env, "TENUO_CLAUDE_BIN": str(tmp_path / "missing")}
    assert tp.decide({"cwd": str(proj)}, e)[0] == tp.DENY_CLI_MISSING


def test_deny_json_matches_cli_guard_shape():
    ours = json.loads(tp.deny_json("x"))
    guard = json.loads(cli._GUARD_DENY_JSON)
    assert ours.keys() == guard.keys()
    assert ours["hookSpecificOutput"].keys() == guard["hookSpecificOutput"].keys()
    for key in ("hookEventName", "permissionDecision"):
        assert ours["hookSpecificOutput"][key] == guard["hookSpecificOutput"][key]


# ---------------------------------------------------------------------------
# End to end through the sh entry point (what Claude Code runs)
# ---------------------------------------------------------------------------


def test_e2e_unrelated_repo_is_silent(tmp_path, env):
    repo = tmp_path / "repo"
    repo.mkdir()
    for mode in ("pre", "post"):
        proc = run_hook(mode, {**PRE_EVENT, "cwd": str(repo)}, {**env, "CLAUDE_PROJECT_DIR": str(repo)}, repo)
        assert proc.returncode == 0 and proc.stdout == b"", proc


def test_e2e_not_initialized_and_disabled_are_silent(tmp_path, env):
    for proj in (make_project(tmp_path / "a", state=False), make_project(tmp_path / "b", disabled=True)):
        proc = run_hook("pre", {**PRE_EVENT, "cwd": str(proj)}, env, proj)
        assert proc.returncode == 0 and proc.stdout == b"", proc


def test_e2e_already_wired_does_not_call_cli(tmp_path, env, monkeypatch):
    proj = make_project(tmp_path / "p")
    wire_like_bootstrap(monkeypatch, proj)
    calls = tmp_path / "calls"
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", f'echo "$@" >> "{calls}"; exit 1')
    proc = run_hook("pre", {**PRE_EVENT, "cwd": str(proj)}, {**env, "CLAUDE_PROJECT_DIR": str(proj)}, proj)
    assert proc.returncode == 0 and proc.stdout == b""
    assert not calls.exists(), "must not double-enforce when bootstrap hooks are wired"


def test_e2e_delegates_event_and_passes_decision_through(tmp_path, env):
    proj = make_project(tmp_path / "p")
    seen = tmp_path / "seen"
    allow = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                        "permissionDecision": "allow", "permissionDecisionReason": "Tenuo authorized: Read"}})
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude",
             f'echo "$1|$TENUO_PROJECT_DIR|$(pwd -P)" > "{seen}"; cat >> "{seen}"; printf \'%s\\n\' \'{allow}\'')
    sub = proj / "sub"
    sub.mkdir()
    proc = run_hook("pre", {**PRE_EVENT, "cwd": str(sub)}, env, sub)
    assert proc.returncode == 0, proc
    assert json.loads(proc.stdout) == json.loads(allow)
    first, rest = seen.read_text().split("\n", 1)
    assert first == f"_hook|{proj.resolve()}|{proj.resolve()}"
    assert json.loads(rest)["tool_name"] == "Read", "hook must receive the raw event on stdin"


def test_e2e_cli_deny_passes_through(tmp_path, env):
    proj = make_project(tmp_path / "p")
    deny = tp.deny_json("Tenuo denied Read: path outside workspace")
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", f"cat >/dev/null; printf '%s\\n' '{deny}'")
    proc = run_hook("pre", {**PRE_EVENT, "cwd": str(proj)}, env, proj)
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_e2e_dry_run_empty_output_stays_neutral(tmp_path, env):
    """`mode: dry-run` prints nothing on purpose; the plugin must not invent a deny."""
    proj = make_project(tmp_path / "p")
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "cat >/dev/null; exit 0")
    proc = run_hook("pre", {**PRE_EVENT, "cwd": str(proj)}, env, proj)
    assert proc.returncode == 0 and proc.stdout.strip() == b""


def test_e2e_cli_missing_fails_closed(tmp_path, env):
    proj = make_project(tmp_path / "p")
    proc = run_hook("pre", {**PRE_EVENT, "cwd": str(proj)}, env, proj)
    assert_deny(proc, "uv tool install tenuo-claude-code")
    assert b"fail-closed" in proc.stderr


@pytest.mark.parametrize("body,needle", [
    ("cat >/dev/null; echo boom >&2; exit 1", "exited 1: boom"),
    ("cat >/dev/null; echo 'not json'", "unreadable decision"),
    ("cat >/dev/null; echo '{\"ok\": true}'", "unreadable decision"),
    ("exit 127", "exited 127"),
])
def test_e2e_cli_errors_fail_closed(tmp_path, env, body, needle):
    proj = make_project(tmp_path / "p")
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", body)
    assert_deny(run_hook("pre", {**PRE_EVENT, "cwd": str(proj)}, env, proj), needle)


def test_e2e_cli_timeout_fails_closed(tmp_path, env):
    proj = make_project(tmp_path / "p")
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "sleep 10")
    proc = run_hook("pre", {**PRE_EVENT, "cwd": str(proj)}, {**env, "TENUO_PLUGIN_HOOK_TIMEOUT": "1"}, proj)
    assert_deny(proc, "timed out")


def test_e2e_cli_exit_2_is_preserved(tmp_path, env):
    proj = make_project(tmp_path / "p")
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "cat >/dev/null; echo blocked >&2; exit 2")
    proc = run_hook("pre", {**PRE_EVENT, "cwd": str(proj)}, env, proj)
    assert proc.returncode == 2 and b"blocked" in proc.stderr


def test_e2e_bad_tenuo_project_dir_fails_closed(tmp_path, env):
    bad = tmp_path / "bad"
    bad.mkdir()
    proc = run_hook("pre", PRE_EVENT, {**env, "TENUO_PROJECT_DIR": str(bad)}, bad)
    assert_deny(proc, "TENUO_PROJECT_DIR")


def test_e2e_post_delegates_and_never_blocks(tmp_path, env):
    proj = make_project(tmp_path / "p")
    seen = tmp_path / "seen"
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", f'echo "$1" > "{seen}"; cat >/dev/null; exit 1')
    proc = run_hook("post", {**PRE_EVENT, "cwd": str(proj)}, env, proj)
    assert proc.returncode == 0 and proc.stdout == b""
    assert seen.read_text().strip() == "_post"
    # CLI missing on post: nothing to block, stay silent.
    other = make_project(tmp_path / "q")
    proc = run_hook("post", {**PRE_EVENT, "cwd": str(other)}, env, other)
    assert proc.returncode == 0 and proc.stdout == b""


@pytest.mark.parametrize("setup,needle", [
    ("none", "Tenuo not configured here"),
    ("uninit", "not initialized"),
    ("disabled", "disabled"),
    ("nocli", "denied until this is fixed"),
    ("delegate", "via the Tenuo plugin"),
])
def test_e2e_session_start_one_line_never_blocks(tmp_path, env, setup, needle):
    proj = tmp_path / "p"
    if setup == "none":
        proj.mkdir()
    else:
        make_project(proj, state=setup != "uninit", disabled=setup == "disabled")
    if setup == "delegate":
        fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "exit 0")
    proc = run_hook("session-start", {"hook_event_name": "SessionStart", "cwd": str(proj)},
                    {**env, "CLAUDE_PROJECT_DIR": str(proj)}, proj)
    assert proc.returncode == 0
    msg = json.loads(proc.stdout)["systemMessage"]
    assert needle in msg and "\n" not in msg


def test_session_start_hint_is_shown_once_in_unrelated_projects(tmp_path, env):
    """A project that never asked for Tenuo hears about setup once, then nothing."""
    repo = tmp_path / "repo"
    repo.mkdir()
    data = tmp_path / "plugin-data"
    with_data = {**env, "CLAUDE_PROJECT_DIR": str(repo), "CLAUDE_PLUGIN_DATA": str(data)}
    event = {"hook_event_name": "SessionStart", "cwd": str(repo)}
    first = run_hook("session-start", event, with_data, repo)
    assert first.returncode == 0
    assert "/tenuo:setup" in json.loads(first.stdout)["systemMessage"]
    for _ in range(2):
        again = run_hook("session-start", event, with_data, repo)
        assert again.returncode == 0 and again.stdout == b""
    # A governed project always gets its status line.
    proj = make_project(tmp_path / "p")
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "exit 0")
    governed = run_hook("session-start", {**event, "cwd": str(proj)},
                        {**with_data, "CLAUDE_PROJECT_DIR": str(proj)}, proj)
    assert "via the Tenuo plugin" in json.loads(governed.stdout)["systemMessage"]


def test_e2e_no_python_fallback(tmp_path, env):
    """Without a usable python3 the sh fallback still fails closed, but only
    in an opted-in project."""
    no_py = {**env, "TENUO_PLUGIN_PYTHON": str(tmp_path / "no-python")}
    repo = tmp_path / "repo"
    repo.mkdir()
    proc = run_hook("pre", PRE_EVENT, {**no_py, "CLAUDE_PROJECT_DIR": str(repo)}, repo)
    assert proc.returncode == 0 and proc.stdout == b""

    proj = make_project(tmp_path / "p")
    proc = run_hook("pre", PRE_EVENT, {**no_py, "CLAUDE_PROJECT_DIR": str(proj)}, proj)
    assert_deny(proc, "python3 was not found")

    make_project(proj, disabled=True)
    proc = run_hook("pre", PRE_EVENT, {**no_py, "CLAUDE_PROJECT_DIR": str(proj)}, proj)
    assert proc.returncode == 0 and proc.stdout == b""


# ---------------------------------------------------------------------------
# Plugin files and CLI integration
# ---------------------------------------------------------------------------


def test_hooks_json_wires_the_launcher_with_safe_timeouts():
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
    assert set(hooks) == {"SessionStart", "PreToolUse", "PostToolUse"}
    for event, mode in (("SessionStart", "session-start"), ("PreToolUse", "pre"), ("PostToolUse", "post")):
        (entry,) = hooks[event]
        (hook,) = entry["hooks"]
        assert hook["command"] == f'"${{CLAUDE_PLUGIN_ROOT}}/scripts/tenuo-hook" {mode}'
    pre_timeout = hooks["PreToolUse"][0]["hooks"][0]["timeout"]
    # Claude lets a timed-out PreToolUse hook through, so the launcher must give
    # up (and deny) first, and must outlast the longest CLI approval poll.
    assert tp.PRE_TIMEOUT_DEFAULT < pre_timeout
    assert tp.PRE_TIMEOUT_DEFAULT >= cli.APPROVAL_POLL_SECONDS + 30
    assert os.access(HOOK_SH, os.X_OK)


def test_manifests_are_consistent():
    plugin = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    market = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text())
    (entry,) = market["plugins"]
    assert plugin["name"] == entry["name"] == "tenuo"
    assert (REPO / entry["source"]).resolve() == PLUGIN.resolve()
    assert plugin["license"] == "Apache-2.0"
    # The plugin must not ship a top-level bin/: Claude adds it to the Bash PATH
    # and the repo's bin/tenuo-claude is a checkout launcher, not a global CLI.
    assert not (PLUGIN / "bin").exists()


def run_wrapper(path: str, cwd: Path, env: dict, **extra) -> subprocess.CompletedProcess:
    """The hook wrapper as Claude Code runs it: no pinned interpreter."""
    return subprocess.run([str(HOOK_SH), "pre"], input=json.dumps(PRE_EVENT).encode(),
                          capture_output=True, cwd=str(cwd), timeout=60,
                          env={**env, "PATH": path, **extra})


def test_hook_wrapper_judges_interpreters_against_the_governing_project(tmp_path, env):
    """The policy can sit above the session directory, or be named by
    TENUO_PROJECT_DIR. An interpreter anywhere in that project is the project's."""
    ran = tmp_path / "ran"
    own_python = fake_cli(tmp_path / "pybin" / "python3", f'exec "{sys.executable}" "$@"')
    repo = make_project(tmp_path / "repo", state=False)
    fake_cli(repo / "bin" / "python3", f"echo ran > {ran}")
    sub = repo / "sub"
    sub.mkdir()
    path = f"{repo / 'bin'}:{own_python.parent}:{env['PATH']}"

    # Session in a subdirectory of the governed project.
    proc = run_wrapper(path, sub, env, CLAUDE_PROJECT_DIR=str(sub))
    assert proc.returncode == 0 and proc.stdout == b"" and not ran.exists()

    # Session somewhere else, project named by the override.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    proc = run_wrapper(path, elsewhere, env, CLAUDE_PROJECT_DIR=str(elsewhere),
                       TENUO_PROJECT_DIR=str(repo))
    assert not ran.exists()
    assert proc.returncode == 0 and proc.stdout == b""


HELPERS = ("readlink", "dirname", "basename", "sed", "tr", "cut", "sha256sum", "shasum", "pwd", "printf")


def test_hook_wrapper_finds_its_own_helpers_on_a_system_path(tmp_path, env):
    """The wrapper screens PATH, so it must not look its own helpers up there:
    a project's `bin/readlink` would run before anything was decided."""
    ran = tmp_path / "ran"
    own_python = fake_cli(tmp_path / "pybin" / "python3", f'exec "{sys.executable}" "$@"')
    linked = tmp_path / "linked-bin"
    linked.mkdir()
    (linked / "python3").symlink_to(own_python)        # makes the wrapper follow a link

    def with_helpers(project: Path) -> str:
        for helper in HELPERS:
            fake_cli(project / "bin" / helper, f"echo {helper} >> {ran}")
        return f"{project / 'bin'}:{linked}:{env['PATH']}"

    # Not set up: the launcher runs with the user's interpreter and stays neutral.
    cloned = make_project(tmp_path / "cloned", state=False)
    proc = run_wrapper(with_helpers(cloned), cloned, env, CLAUDE_PROJECT_DIR=str(cloned))
    assert proc.returncode == 0 and proc.stdout == b""
    assert not ran.exists()

    # Set up, but no interpreter: the shell fallback hashes the project path and
    # denies, still without touching the project's helpers.
    mine = make_project(tmp_path / "mine")
    proc = run_wrapper(with_helpers(mine), mine, env, CLAUDE_PROJECT_DIR=str(mine),
                       TENUO_PLUGIN_PYTHON="/missing")
    assert_deny(proc, "python3 was not found")
    assert not ran.exists()


def test_hook_wrapper_finds_the_policy_through_a_linked_session_directory(tmp_path, env):
    """Started in a link to `repo/sub`, the policy is still `repo/tenuo.yaml`."""
    ran = tmp_path / "ran"
    own_python = fake_cli(tmp_path / "pybin" / "python3", f'exec "{sys.executable}" "$@"')
    repo = make_project(tmp_path / "repo", state=False)
    fake_cli(repo / "bin" / "python3", f"echo ran > {ran}")
    (repo / "sub").mkdir()
    link = tmp_path / "link"
    link.symlink_to(repo / "sub")
    path = f"{repo / 'bin'}:{own_python.parent}:{env['PATH']}"
    proc = run_wrapper(path, link, env, CLAUDE_PROJECT_DIR=str(link), PWD=str(link))
    assert proc.returncode == 0 and proc.stdout == b""
    assert not ran.exists()


def test_hook_wrapper_follows_a_linked_interpreter_into_the_project(tmp_path, env):
    """A `python3` outside the project that is a link to a file inside it."""
    ran = tmp_path / "ran"
    own_python = fake_cli(tmp_path / "pybin" / "python3", f'exec "{sys.executable}" "$@"')
    proj = make_project(tmp_path / "cloned", state=False)
    target = fake_cli(proj / "tools" / "run-me", f"echo ran > {ran}")
    outside = tmp_path / "outside-bin"
    outside.mkdir()
    (outside / "python3").symlink_to(target)
    # A chain of links, ending in the project.
    chained = tmp_path / "chained-bin"
    chained.mkdir()
    (chained / "python3").symlink_to(outside / "python3")
    # A link that goes nowhere is dropped, not run and not fatal.
    broken = tmp_path / "broken-bin"
    broken.mkdir()
    (broken / "python3").symlink_to(tmp_path / "missing")
    path = f"{chained}:{outside}:{broken}:{own_python.parent}:{env['PATH']}"
    proc = run_wrapper(path, proj, env, CLAUDE_PROJECT_DIR=str(proj))
    assert not ran.exists()
    assert proc.returncode == 0 and proc.stdout == b""


def run_skill_command(args: list[str], env: dict, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPTS / "tenuo_plugin.py"), "run", *args],
                          capture_output=True, text=True, cwd=str(cwd), env=env, timeout=60)


def user_cli(home: Path, body: str) -> Path:
    """A fake `tenuo-claude` installed for the user, outside any project."""
    return fake_cli(home / ".local" / "bin" / "tenuo-claude", body)


def test_run_exits_zero_and_reports_the_outcome_in_its_output(tmp_path, env, home):
    """Claude Code drops a skill whose injected command exits non-zero, so the
    skill runner must exit 0 and say what happened in the text instead."""
    proj = make_project(tmp_path / "p")
    user_cli(home, "echo checked; exit 3")
    proc = run_skill_command(["status"], env, proj)
    assert proc.returncode == 0
    assert "checked" in proc.stdout
    assert proc.stdout.rstrip().endswith("[tenuo-claude exited 3]")

    user_cli(home, "echo checked")
    proc = run_skill_command(["status"], env, proj)
    assert proc.returncode == 0 and "exited" not in proc.stdout


def test_run_without_policy_says_tenuo_is_not_set_up(tmp_path, env, home):
    empty = tmp_path / "empty"
    empty.mkdir()
    proc = run_skill_command(["status"], env, empty)
    assert proc.returncode == 0
    assert "Tenuo is not set up here" in proc.stdout and "/tenuo:setup" in proc.stdout
    assert "CLI: not installed" in proc.stdout
    assert f"Project: {empty.resolve()}" in proc.stdout or f"Project: {empty}" in proc.stdout
    assert "unfinished" not in proc.stdout

    cli_path = user_cli(home, "exit 0")
    proc = run_skill_command(["--version"], env, empty)
    assert "Tenuo is not set up here" in proc.stdout
    assert f"CLI: found at {cli_path}" in proc.stdout

    # Cloud credentials without a policy are an unfinished setup, not a blank slate.
    (empty / ".state").mkdir()
    (empty / ".state" / "cloud.env").write_text("x\n")
    proc = run_skill_command(["status"], env, empty)
    assert "Found Cloud credentials" in proc.stdout and "unfinished Cloud setup" in proc.stdout


def test_run_finds_a_cli_in_the_project_virtualenv_before_a_policy_exists(tmp_path, env):
    """Setup trusts this line. A CLI that is only in the project's .venv must be
    reported, or setup installs a second one."""
    proj = tmp_path / "fresh"
    proj.mkdir()
    cli_path = fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "exit 0")
    by_cwd = run_skill_command(["--version"], env, proj)
    assert f"CLI: found at {cli_path}" in by_cwd.stdout
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    by_session = run_skill_command(["--version"], {**env, "CLAUDE_PROJECT_DIR": str(proj)}, elsewhere)
    assert f"CLI: found at {cli_path}" in by_session.stdout
    assert f"Project: {proj}" in by_session.stdout


@pytest.mark.parametrize("overlay", ["tenuo.cloud.yaml", "tenuo.advanced.yaml"])
def test_run_flags_a_cloud_overlay_without_a_policy(tmp_path, env, overlay):
    """Local bootstrap moves Cloud overlays aside, so setup must not treat a
    directory that has one as a blank slate."""
    proj = tmp_path / "half"
    proj.mkdir()
    (proj / overlay).write_text("cloud: {}\n")
    proc = run_skill_command(["status"], env, proj)
    assert proc.returncode == 0
    assert f"Found {overlay}" in proc.stdout and "unfinished Cloud setup" in proc.stdout


@pytest.mark.parametrize("args", [
    ["disable"], ["uninstall", "--yes"], ["bootstrap", "--native"], ["init"], ["up"],
    ["refresh"], ["revoke"], ["check"], ["verify"], ["verify", "--deep"],
    ["audit", "--verify", "--oops"], [],
])
def test_run_refuses_anything_that_is_not_a_read_only_command(tmp_path, env, home, args):
    """The skills pre-approve this script, so it must not be a way to change
    governance, or to run a project's own scripts, without the user seeing the
    command. `check` and `verify` are refused for the second reason."""
    proj = make_project(tmp_path / "p")
    called = tmp_path / "called"
    user_cli(home, f"echo ran > {called}")
    proc = run_skill_command(args, env, proj)
    assert proc.returncode == 0
    assert "read-only commands only" in proc.stdout
    assert not called.exists()


@pytest.mark.parametrize("args", [
    ["status"], ["state-dir"], ["--version"],
    ["audit"], ["audit", "--verify"], ["audit", "--tail", "20"],
])
def test_run_passes_read_only_commands_through(tmp_path, env, home, args):
    proj = make_project(tmp_path / "p")
    seen = tmp_path / "seen"
    cli_path = user_cli(home, f'echo "$@" > {seen}')
    proc = run_skill_command(args, env, proj)
    assert proc.returncode == 0
    assert f"CLI: {cli_path}" in proc.stdout
    assert f"Project: {proj.resolve()}" in proc.stdout
    assert seen.read_text().split() == args


def test_run_does_not_execute_a_project_copy_of_the_cli_before_setup(tmp_path, env, home):
    """A repository can ship a policy, a `.state` folder and a `.venv`. None of
    that makes its `tenuo-claude` something to run without asking."""
    proj = make_project(tmp_path / "cloned", in_project_state=True)   # tenuo.yaml + its own .state
    ran = tmp_path / "ran"
    local = fake_cli(proj / ".venv" / "bin" / "tenuo-claude", f"echo ran > {ran}")
    proc = run_skill_command(["status"], env, proj)
    assert proc.returncode == 0
    assert not ran.exists()
    assert f"inside this project ({local})" in proc.stdout

    # With a CLI of the user's own, that one runs instead.
    mine = tmp_path / "mine"
    cli_path = user_cli(home, f"echo mine > {mine}")
    proc = run_skill_command(["status"], env, proj)
    assert f"CLI: {cli_path}" in proc.stdout
    assert mine.exists() and not ran.exists()

    # Once the user has set the project up here (state under their home), the
    # project's own environment is theirs, as it is for the hooks.
    cli_path.unlink()
    (proj / ".state" / "state.json").unlink()
    state = tp.project_state_dir(proj, env)
    state.mkdir(parents=True)
    proc = run_skill_command(["status"], env, proj)
    assert not ran.exists(), "an empty state directory is not proof of setup"
    (state / "state.json").write_text("{}")
    proc = run_skill_command(["status"], env, proj)
    assert f"CLI: {local}" in proc.stdout and ran.exists()


def test_run_is_not_fooled_by_links_or_by_path(tmp_path, env, home):
    """Everything here is something a repository can arrange for itself."""
    proj = make_project(tmp_path / "cloned", state=False)
    ran = tmp_path / "ran"
    outside = fake_cli(tmp_path / "elsewhere" / "tool", f"echo ran > {ran}")

    # 1. The project's copy is a link to a program outside the project.
    link = proj / ".venv" / "bin" / "tenuo-claude"
    link.parent.mkdir(parents=True)
    link.symlink_to(outside)
    proc = run_skill_command(["status"], env, proj)
    assert not ran.exists() and "inside this project" in proc.stdout

    # 2. The project's virtualenv is on PATH, or named by the override.
    on_path = {**env, "PATH": f"{link.parent}:{env['PATH']}"}
    assert not ran.exists() and "inside this project" in run_skill_command(["status"], on_path, proj).stdout
    by_override = run_skill_command(["status"], {**env, "TENUO_CLAUDE_BIN": str(link)}, proj)
    assert not ran.exists() and "CLI:" not in by_override.stdout

    # 3. The project carries a `.state` that links to a directory elsewhere, or
    #    points TENUO_STATE_DIR back into itself.
    real_state = tmp_path / "planted-state"
    real_state.mkdir()
    (real_state / "state.json").write_text("{}")
    (proj / ".state").symlink_to(real_state)
    assert "inside this project" in run_skill_command(["status"], env, proj).stdout
    inward = run_skill_command(["status"], {**env, "TENUO_STATE_DIR": str(proj / ".state")}, proj)
    assert "inside this project" in inward.stdout
    assert not ran.exists()


def test_run_looks_past_a_project_copy_on_path_to_the_users_own(tmp_path, env):
    """The project's virtualenv first on PATH must not hide a CLI later on it."""
    proj = make_project(tmp_path / "cloned", state=False)
    ran = tmp_path / "ran"
    local = fake_cli(proj / ".venv" / "bin" / "tenuo-claude", f"echo ran > {ran}")
    mine = tmp_path / "mine"
    system = fake_cli(tmp_path / "usr-local-bin" / "tenuo-claude", f"echo mine > {mine}")
    path = f"{local.parent}:{system.parent}:{env['PATH']}"
    proc = run_skill_command(["status"], {**env, "PATH": path}, proj)
    assert f"CLI: {system}" in proc.stdout
    assert mine.exists() and not ran.exists()


def test_a_relative_cli_path_is_pinned_before_it_is_checked_or_run(tmp_path, env):
    """The CLI runs with the project as its working directory. A relative PATH
    entry or override must not be checked in the shell's directory and then
    run from the project's."""
    proj = make_project(tmp_path / "cloned", state=False)
    ran = tmp_path / "ran"
    fake_cli(proj / "bin" / "tenuo-claude", f"echo ran > {ran}")       # the project's file
    shell_dir = tmp_path / "shell"
    mine = tmp_path / "mine"
    own = fake_cli(shell_dir / "bin" / "tenuo-claude", f"echo mine > {mine}")
    session = {**env, "CLAUDE_PROJECT_DIR": str(proj)}

    by_path = run_skill_command(["status"], {**session, "PATH": f"bin:{env['PATH']}"}, shell_dir)
    assert f"CLI: {own}" in by_path.stdout
    assert mine.exists() and not ran.exists()

    mine.unlink()
    by_override = run_skill_command(
        ["status"], {**session, "TENUO_CLAUDE_BIN": "bin/tenuo-claude"}, shell_dir)
    assert f"CLI: {own}" in by_override.stdout
    assert mine.exists() and not ran.exists()

    # Run from inside the project, the same relative spellings name the
    # project's file, and that one is refused before setup.
    mine.unlink()
    inside = run_skill_command(["status"], {**session, "PATH": f"bin:{env['PATH']}"}, proj)
    assert "inside this project" in inside.stdout
    assert not ran.exists() and not mine.exists()
    assert tp.find_cli(None, {"PATH": "relative-dir", "HOME": str(tmp_path)}) is None


def test_inside_judges_by_location_and_by_target(tmp_path):
    root = tmp_path / "proj"
    (root / "sub").mkdir(parents=True)
    outside = tmp_path / "out"
    outside.mkdir()
    (root / "link-out").symlink_to(outside)
    (outside / "link-in").symlink_to(root / "sub")
    assert tp._inside(root / "sub" / "x", root)
    assert tp._inside(root / "link-out", root)           # sits inside
    assert tp._inside(outside / "link-in", root)         # points inside
    assert tp._inside(root / "sub" / ".." / "y", root)
    assert not tp._inside(outside / "z", root)
    assert not tp._inside(tmp_path / "proj-sibling", root)


def test_run_keeps_inspection_failures_apart_from_no_policy(tmp_path, env):
    """A missing CLI or a broken TENUO_PROJECT_DIR is not "Tenuo is off": the
    hooks deny calls in both cases, and earlier receipts may still exist."""
    proj = make_project(tmp_path / "p")
    proc = run_skill_command(["audit", "--verify"], env, proj)
    assert proc.returncode == 0
    assert "denied until this is fixed" in proc.stdout
    assert "`tenuo-claude audit --verify` could not run" in proc.stdout
    assert "not set up here" not in proc.stdout

    empty = tmp_path / "empty"
    empty.mkdir()
    proc = run_skill_command(["status"], {**env, "TENUO_PROJECT_DIR": str(empty)}, empty)
    assert proc.returncode == 0
    assert "denied until this is fixed" in proc.stdout and "has no tenuo.yaml" in proc.stdout
    assert "not set up here" not in proc.stdout


SKILL_GRANT = 'Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run *)'
SKILL_COMMAND_PREFIX = 'python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run '


@pytest.mark.parametrize("name", ["setup", "status", "audit"])
def test_skills_can_be_invoked_by_claude_with_a_narrow_grant(name):
    text = (PLUGIN / "skills" / name / "SKILL.md").read_text()
    _, front, body = text.split("---\n", 2)
    meta = dict(line.split(": ", 1) for line in front.strip().splitlines())
    assert meta["name"] == name
    # Claude must be able to find and start the skill from a plain request.
    assert "disable-model-invocation" not in meta
    assert "Use when" in meta["description"] and len(meta["description"]) <= 1536
    # The grant covers the bundled launcher only, never an open `python3 *`.
    assert meta["allowed-tools"] == SKILL_GRANT
    injected = [line[2:-1] for line in body.splitlines()
                if line.startswith("!`") and line.endswith("`")]
    assert injected, "skill should inject launcher output"
    for command in injected:
        assert command.startswith(SKILL_COMMAND_PREFIX)
        # Plain arguments only: a redirect, pipe or chained command would fall
        # outside the grant and abort the skill.
        assert re.fullmatch(r"[a-z]+( --?[a-z-]+)*", command[len(SKILL_COMMAND_PREFIX):])


def test_disable_marker_round_trip(monkeypatch, tmp_path):
    """`disable` makes the plugin stand down; re-wiring (init/refresh) re-arms it."""
    proj = make_project(tmp_path / "p")
    wire_like_bootstrap(monkeypatch, proj)
    monkeypatch.setattr(cli, "_teardown_cfg", lambda: {"name": "test"})
    monkeypatch.setattr(cli, "_stop_authorizer", lambda _cfg: False)
    monkeypatch.setattr(cli, "managed_mode", lambda _cfg: False)

    cli.cmd_disable(types.SimpleNamespace())
    assert (state_dir(proj) / "disabled").is_file()
    env = {"HOME": str(tmp_path / "home"), "PATH": "/usr/bin:/bin", "CLAUDE_PROJECT_DIR": str(proj)}
    monkeypatch.setattr(tp, "MANAGED_SETTINGS_PATHS", ())
    assert tp.decide({"cwd": str(proj)}, env)[0] == tp.NOOP_DISABLED

    cli.write_claude_wiring({"name": "test", "approval": {}})
    assert not (state_dir(proj) / "disabled").exists()
    assert tp.decide({"cwd": str(proj)}, env)[0] == tp.NOOP_ALREADY_WIRED


def test_disable_without_state_writes_no_marker(monkeypatch, tmp_path):
    proj = make_project(tmp_path / "p", state=False)
    wire_like_bootstrap(monkeypatch, proj)
    monkeypatch.setattr(cli, "_teardown_cfg", lambda: {"name": "test"})
    monkeypatch.setattr(cli, "_stop_authorizer", lambda _cfg: False)
    monkeypatch.setattr(cli, "managed_mode", lambda _cfg: False)
    cli.cmd_disable(types.SimpleNamespace())
    assert not (proj / ".state").exists() and not state_dir(proj).exists()


@pytest.mark.parametrize("matcher", ["Read", "Read|Edit", "mcp__.*"])
def test_partial_wiring_never_disables_plugin(tmp_path, env, matcher):
    proj = make_project(tmp_path / "p")
    (proj / ".claude").mkdir()
    (proj / ".claude/settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": matcher, "hooks": [{"type": "command", "command": "tenuo-claude _hook"}]}]}}))
    fake_cli(proj / ".venv/bin/tenuo-claude", "exit 2")
    event = {"cwd": str(proj), "tool_name": "Bash", "tool_input": {"command": "pwd"}}
    assert tp.decide(event, env)[0] == tp.DELEGATE
    assert run_hook("pre", event, env, proj).returncode == 2
    assert run_hook("pre", event, {**env, "TENUO_PLUGIN_PYTHON": "/missing"}, proj).returncode == 2


@pytest.mark.parametrize("name", ["project", "My_Project !", "a" * 80])
def test_plugin_state_matches_cli_and_survives_migration(tmp_path, env, monkeypatch, name):
    from tenuo_claude_code import paths
    proj = make_project(tmp_path / name, in_project_state=True)
    monkeypatch.setenv("HOME", env["HOME"])
    monkeypatch.delenv("TENUO_STATE_DIR", raising=False)
    assert tp.project_state_dir(proj, env) == paths.project_state_dir(proj)
    # State inside the project is where an older version left it. The plugin
    # does not act on it; `refresh` moves it to the user's home.
    before = {**PRE_EVENT, "cwd": str(proj)}
    assert tp.decide(before, env)[0] == tp.NOOP_STATE_IN_PROJECT
    for no_py in (env, {**env, "TENUO_PLUGIN_PYTHON": "/missing"}):
        silent = run_hook("pre", before, no_py, proj) if no_py is env else subprocess.run(
            [str(HOOK_SH), "pre"], input=json.dumps(before).encode(), capture_output=True,
            cwd=str(proj), env=no_py, timeout=60)
        assert silent.returncode == 0 and silent.stdout == b""
    state = paths.home_state_dir(proj)
    state.parent.mkdir(parents=True, exist_ok=True)
    (proj / ".state").rename(state)
    assert tp.project_state_dir(proj, env) == paths.project_state_dir(proj) == state
    event = {**PRE_EVENT, "cwd": str(proj)}
    assert tp.decide(event, env)[0] == tp.DENY_CLI_MISSING
    assert_deny(run_hook("pre", event, env, proj), "CLI was not found")
    no_python = {**env, "TENUO_PLUGIN_PYTHON": "/missing"}
    assert_deny(run_hook("pre", event, no_python, proj), "python3 was not found")
    monkeypatch.setattr(cli, "STATE", state, raising=False)
    cli.set_disabled_marker(True)
    assert tp.decide(event, env)[0] == tp.NOOP_DISABLED
    assert run_hook("pre", event, no_python, proj).returncode == 0
    cli.set_disabled_marker(False)
    assert tp.decide(event, env)[0] == tp.DENY_CLI_MISSING


def test_plugin_state_override(tmp_path, env, monkeypatch):
    from tenuo_claude_code import paths
    proj = make_project(tmp_path / "p")
    state = tmp_path / "custom-state"
    state.mkdir()
    env = {**env, "TENUO_STATE_DIR": str(state)}
    monkeypatch.setenv("TENUO_STATE_DIR", str(state))
    assert tp.project_state_dir(proj, env) == paths.project_state_dir(proj) == state
    (state / "disabled").write_text("disabled")
    # A directory with no state.json is not a set-up project, wherever it is.
    assert tp.decide({"cwd": str(proj)}, env)[0] == tp.NOOP_NOT_INITIALIZED
    (state / "state.json").write_text("{}")
    assert tp.decide({"cwd": str(proj)}, env)[0] == tp.NOOP_DISABLED


def test_state_a_project_carries_is_not_setup(tmp_path, env, monkeypatch):
    """A repository can ship a policy, a `.state` folder and a `.venv`. The
    plugin must run nothing of theirs and enforce nothing on their say-so."""
    proj = make_project(tmp_path / "cloned", in_project_state=True)
    ran = tmp_path / "ran"
    fake_cli(proj / ".venv" / "bin" / "tenuo-claude", f"echo ran > {ran}")
    session = {**env, "CLAUDE_PROJECT_DIR": str(proj)}
    event = {**PRE_EVENT, "cwd": str(proj)}

    assert tp.decide(event, session)[0] == tp.NOOP_STATE_IN_PROJECT
    for mode in ("pre", "post"):
        proc = run_hook(mode, event, session, proj)
        assert proc.returncode == 0 and proc.stdout == b""
    line = json.loads(run_hook("session-start", {"cwd": str(proj)}, session, proj).stdout)["systemMessage"]
    assert "inside the project" in line and "NOT governed" in line
    assert not ran.exists()

    # The same through a link, or through TENUO_STATE_DIR pointing back in.
    linked = make_project(tmp_path / "linked", state=False)
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "state.json").write_text("{}")
    (linked / ".state").symlink_to(planted)
    assert tp.decide({"cwd": str(linked)}, env)[0] == tp.NOOP_STATE_IN_PROJECT
    inward = {**env, "TENUO_STATE_DIR": str(proj / ".state")}
    assert tp.decide(event, inward)[0] == tp.NOOP_STATE_IN_PROJECT

    # Hooks the CLI wired into Claude's settings are Claude Code's to run; the
    # plugin still reports them as what governs the project.
    wire_like_bootstrap(monkeypatch, proj, tmp_path / "home")
    assert tp.decide(event, session)[0] == tp.NOOP_ALREADY_WIRED


def test_hooks_use_the_users_cli_before_the_projects_copy(tmp_path, env, home):
    proj = make_project(tmp_path / "p")
    local = fake_cli(proj / ".venv" / "bin" / "tenuo-claude", "exit 0")
    event = {"cwd": str(proj)}
    # Only the project's copy exists, in a project this user set up: use it.
    assert tp.decide(event, env)[2] == str(local)
    # With a CLI of the user's own, that one wins.
    mine = fake_cli(home / ".local" / "bin" / "tenuo-claude", "exit 0")
    assert tp.decide(event, env)[2] == str(mine)
    assert tp.resolve_cli(proj, env) == (str(mine), None)


def test_hook_wrapper_skips_an_interpreter_inside_the_project(tmp_path, env):
    """`python3` is looked up on PATH. One that sits inside the project is the
    project's file, and is not what should run the launcher."""
    ran = tmp_path / "ran"
    event = json.dumps(PRE_EVENT).encode()
    # A python3 of the user's own, in a directory that holds nothing else. (The
    # interpreter's real directory may also hold an installed tenuo-claude.)
    own_python = fake_cli(tmp_path / "pybin" / "python3", f'exec "{sys.executable}" "$@"')
    for name, set_up in (("cloned", False), ("mine", True)):
        proj = make_project(tmp_path / name, state=set_up)
        fake_cli(proj / "bin" / "python3", f"echo ran > {ran}")
        path = f"{proj / 'bin'}:{own_python.parent}:{env['PATH']}"
        proc = subprocess.run([str(HOOK_SH), "pre"], input=event, capture_output=True, cwd=str(proj),
                              env={**env, "PATH": path, "CLAUDE_PROJECT_DIR": str(proj)}, timeout=60)
        assert not ran.exists()
        if set_up:      # the real launcher ran: governed, no CLI, so it denies
            assert_deny(proc, "CLI was not found")
        else:
            assert proc.returncode == 0 and proc.stdout == b""
