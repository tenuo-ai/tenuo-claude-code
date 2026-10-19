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


def make_project(root: Path, *, state=True, disabled=False) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "tenuo.yaml").write_text("name: test\n")
    if state:
        (root / ".state").mkdir(exist_ok=True)
    if disabled:
        (root / ".state" / "disabled").write_text("disabled\n")
    return root


def fake_cli(path: Path, body: str) -> Path:
    """Write an executable fake `tenuo-claude` (POSIX sh)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def wire_like_bootstrap(monkeypatch, project: Path) -> None:
    """Write .claude/settings.json with the REAL bootstrap wiring code."""
    monkeypatch.setattr(cli, "DEMO_DIR", project, raising=False)
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
    inner = make_project(outer / "inner")
    wire_like_bootstrap(monkeypatch, inner)
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


def test_disable_marker_round_trip(monkeypatch, tmp_path):
    """`disable` makes the plugin stand down; re-wiring (init/refresh) re-arms it."""
    proj = make_project(tmp_path / "p")
    wire_like_bootstrap(monkeypatch, proj)
    monkeypatch.setattr(cli, "_teardown_cfg", lambda: {"name": "test"})
    monkeypatch.setattr(cli, "_stop_authorizer", lambda _cfg: False)
    monkeypatch.setattr(cli, "managed_mode", lambda _cfg: False)

    cli.cmd_disable(types.SimpleNamespace())
    assert (proj / ".state" / "disabled").is_file()
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "CLAUDE_PROJECT_DIR": str(proj)}
    monkeypatch.setattr(tp, "MANAGED_SETTINGS_PATHS", ())
    assert tp.decide({"cwd": str(proj)}, env)[0] == tp.NOOP_DISABLED

    cli.write_claude_wiring({"name": "test", "approval": {}})
    assert not (proj / ".state" / "disabled").exists()
    assert tp.decide({"cwd": str(proj)}, env)[0] == tp.NOOP_ALREADY_WIRED


def test_disable_without_state_writes_no_marker(monkeypatch, tmp_path):
    proj = make_project(tmp_path / "p", state=False)
    wire_like_bootstrap(monkeypatch, proj)
    monkeypatch.setattr(cli, "_teardown_cfg", lambda: {"name": "test"})
    monkeypatch.setattr(cli, "_stop_authorizer", lambda _cfg: False)
    monkeypatch.setattr(cli, "managed_mode", lambda _cfg: False)
    cli.cmd_disable(types.SimpleNamespace())
    assert not (proj / ".state").exists()
