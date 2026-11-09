"""Tests for example policy scaffolding and Claude wiring."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import types

import pytest
import yaml

from tenuo_claude_code import cli
from tenuo_claude_code.paths import (
    bundled_template,
    default_policy_name,
    find_project_root,
    scaffold_example_policy,
)


def test_bundled_template_exists():
    path = bundled_template("tenuo.yaml.example")
    assert path.is_file()
    assert "enforce" in path.read_text(encoding="utf-8")


def test_scaffold_writes_example_policy(tmp_path):
    project = tmp_path / "my-app"
    project.mkdir()
    created = scaffold_example_policy(project)
    assert created is True
    policy = project / "tenuo.yaml"
    assert policy.is_file()
    text = policy.read_text(encoding="utf-8")
    assert "Example policy" in text
    assert yaml.safe_load(text)["name"] == "my-app"
    assert (project / "workspace").is_dir()


@pytest.mark.parametrize(
    ("dirname", "expected"),
    [
        ("acme-backend", "acme-backend"),
        ("My Project", "my-project"),
        ("foo__bar", "foo-bar"),
        ("...", "tenuo-claude"),
    ],
)
def test_default_policy_name(dirname, expected, tmp_path):
    path = tmp_path / dirname
    path.mkdir()
    assert default_policy_name(path) == expected


def test_scaffold_uses_directory_name(tmp_path):
    project = tmp_path / "Acme_Backend"
    project.mkdir()
    scaffold_example_policy(project)
    assert yaml.safe_load((project / "tenuo.yaml").read_text())["name"] == "acme-backend"


def test_scaffold_no_op_when_policy_exists(tmp_path):
    (tmp_path / "tenuo.yaml").write_text("name: existing\n")
    assert scaffold_example_policy(tmp_path) is False


def test_scaffold_no_scaffold_raises(tmp_path):
    with pytest.raises(SystemExit, match="Missing tenuo.yaml"):
        scaffold_example_policy(tmp_path, no_scaffold=True)


def test_find_project_root_fallback_cwd(tmp_path, monkeypatch):
    monkeypatch.delenv("TENUO_PROJECT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert find_project_root(fallback_cwd=True) == tmp_path.resolve()


def test_find_project_root_tenuo_project_dir_without_yaml(tmp_path, monkeypatch):
    monkeypatch.setenv("TENUO_PROJECT_DIR", str(tmp_path))
    assert find_project_root(fallback_cwd=True) == tmp_path.resolve()


def test_find_project_dir_env_requires_yaml_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("TENUO_PROJECT_DIR", str(tmp_path))
    with pytest.raises(SystemExit, match="has no tenuo.yaml"):
        find_project_root(fallback_cwd=False)


def test_find_project_root_walks_up(tmp_path, monkeypatch):
    monkeypatch.delenv("TENUO_PROJECT_DIR", raising=False)
    project = tmp_path / "proj"
    nested = project / "sub"
    nested.mkdir(parents=True)
    (project / "tenuo.yaml").write_text("name: p\n")
    monkeypatch.chdir(nested)
    assert find_project_root() == project.resolve()


def test_write_advanced_profile_prefers_stable_approver_id(monkeypatch, tmp_path):
    path = tmp_path / "tenuo.advanced.yaml"
    monkeypatch.setattr(cli, "ADVANCED_PROFILE", path, raising=False)

    cli.write_advanced_profile(approver="Alice Example", approver_id="idn_123")

    data = yaml.safe_load(path.read_text())
    assert data["cloud"] == {"approver_identity_id": "idn_123"}


def test_write_advanced_profile_keeps_display_name_fallback(monkeypatch, tmp_path):
    path = tmp_path / "tenuo.advanced.yaml"
    monkeypatch.setattr(cli, "ADVANCED_PROFILE", path, raising=False)

    cli.write_advanced_profile(approver="Alice Example")

    data = yaml.safe_load(path.read_text())
    assert data["cloud"] == {"approver_identity": "Alice Example"}


def _make_cfg(mcp=False):
    """Minimal config dict for write_claude_wiring tests."""
    cfg: dict = {"name": "test", "approval": {}}
    if mcp:
        cfg["mcp"] = {"downstream": "stdio://unused"}
    return cfg


def _patch_wiring(monkeypatch, tmp_path):
    """Patch module-level globals needed by write_claude_wiring / wiring_command_parts."""
    monkeypatch.setattr(cli, "DEMO_DIR", tmp_path, raising=False)
    monkeypatch.setattr(cli, "APPROVAL_POLL_SECONDS", 30, raising=False)
    monkeypatch.setattr(cli, "LAUNCHER", tmp_path / "bin" / "tenuo-claude", raising=False)
    monkeypatch.setattr(cli, "LAUNCHER_REL", "./bin/tenuo-claude", raising=False)


def test_write_claude_wiring_creates_settings(monkeypatch, tmp_path):
    _patch_wiring(monkeypatch, tmp_path)

    cli.write_claude_wiring(_make_cfg())

    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert "PreToolUse" in settings["hooks"]
    assert "PostToolUse" in settings["hooks"]


def test_write_claude_wiring_preserves_existing_hooks(monkeypatch, tmp_path):
    """Non-Tenuo hooks must survive a wiring refresh."""
    _patch_wiring(monkeypatch, tmp_path)
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    existing = {
        "permissions": {"allow": ["Bash"]},
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}
            ],
        },
    }
    (claude_dir / "settings.json").write_text(json.dumps(existing))

    cli.write_claude_wiring(_make_cfg())

    settings = json.loads((claude_dir / "settings.json").read_text())
    assert settings["permissions"] == {"allow": ["Bash"]}
    pre = settings["hooks"]["PreToolUse"]
    commands = [h["hooks"][0]["command"] for h in pre]
    assert any("echo hi" in c for c in commands), "existing hook was removed"
    assert any("_hook" in c for c in commands), "Tenuo hook was not added"


def test_write_claude_wiring_updates_tenuo_hook_in_place(monkeypatch, tmp_path):
    """Re-running refresh should update the Tenuo hook, not duplicate it."""
    _patch_wiring(monkeypatch, tmp_path)
    cli.write_claude_wiring(_make_cfg())
    cli.write_claude_wiring(_make_cfg())

    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    tenuo_hooks = [
        h for h in settings["hooks"]["PreToolUse"]
        if "_hook" in h.get("hooks", [{}])[0].get("command", "")
    ]
    assert len(tenuo_hooks) == 1, "Tenuo hook was duplicated"


def test_write_claude_wiring_mcp_preserves_other_servers(monkeypatch, tmp_path):
    """Other MCP servers must be kept when Tenuo server is added."""
    _patch_wiring(monkeypatch, tmp_path)
    existing_mcp = {"mcpServers": {"other-server": {"command": "other"}}}
    mcp_path = tmp_path / ".mcp.json"
    mcp_path.write_text(json.dumps(existing_mcp) + "\n")

    cli.write_claude_wiring(_make_cfg(mcp=True))

    mcp = json.loads(mcp_path.read_text())
    assert "other-server" in mcp["mcpServers"]
    assert cli.MCP_SERVER_NAME in mcp["mcpServers"]


def test_write_claude_wiring_mcp_removal_keeps_other_servers(monkeypatch, tmp_path):
    """When MCP downstream is removed, only the Tenuo server is deleted."""
    _patch_wiring(monkeypatch, tmp_path)
    existing_mcp = {
        "mcpServers": {
            "other-server": {"command": "other"},
            cli.MCP_SERVER_NAME: {"command": "tenuo"},
        }
    }
    mcp_path = tmp_path / ".mcp.json"
    mcp_path.write_text(json.dumps(existing_mcp) + "\n")

    cli.write_claude_wiring(_make_cfg(mcp=False))

    mcp = json.loads(mcp_path.read_text())
    assert "other-server" in mcp["mcpServers"]
    assert cli.MCP_SERVER_NAME not in mcp["mcpServers"]


def test_write_claude_wiring_mcp_removal_deletes_file_when_empty(monkeypatch, tmp_path):
    """When the only MCP server is Tenuo's, removing it should delete .mcp.json."""
    _patch_wiring(monkeypatch, tmp_path)
    existing_mcp = {"mcpServers": {cli.MCP_SERVER_NAME: {"command": "tenuo"}}}
    mcp_path = tmp_path / ".mcp.json"
    mcp_path.write_text(json.dumps(existing_mcp) + "\n")

    cli.write_claude_wiring(_make_cfg(mcp=False))

    assert not mcp_path.exists()


# --- remove_claude_wiring (reverse of write_claude_wiring) -----------------

def test_remove_claude_wiring_round_trips(monkeypatch, tmp_path):
    """`disable`/`uninstall` must fully reverse a fresh wiring."""
    _patch_wiring(monkeypatch, tmp_path)
    cli.write_claude_wiring(_make_cfg(mcp=True))
    settings_path = tmp_path / ".claude" / "settings.json"
    mcp_path = tmp_path / ".mcp.json"
    assert settings_path.exists() and mcp_path.exists()

    changed = cli.remove_claude_wiring()

    assert changed, "should report what it removed"
    # Both files held only Tenuo entries, so both are deleted.
    assert not settings_path.exists()
    assert not mcp_path.exists()


def test_remove_claude_wiring_preserves_foreign_config(monkeypatch, tmp_path):
    """User-owned hooks, permissions, and other MCP servers must survive."""
    _patch_wiring(monkeypatch, tmp_path)
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(json.dumps({
        "permissions": {"allow": ["Bash"]},
        "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}
        ]},
    }))
    mcp_path = tmp_path / ".mcp.json"
    mcp_path.write_text(json.dumps({"mcpServers": {"other-server": {"command": "x"}}}) + "\n")

    cli.write_claude_wiring(_make_cfg(mcp=True))
    cli.remove_claude_wiring()

    settings = json.loads((claude_dir / "settings.json").read_text())
    assert settings["permissions"] == {"allow": ["Bash"]}
    pre = settings["hooks"]["PreToolUse"]
    commands = [h["hooks"][0]["command"] for h in pre]
    assert any("echo hi" in c for c in commands), "user hook was removed"
    assert not any("_hook" in c for c in commands), "Tenuo hook was not removed"
    assert "other-server" in json.loads(mcp_path.read_text())["mcpServers"]
    assert cli.MCP_SERVER_NAME not in json.loads(mcp_path.read_text())["mcpServers"]


def test_remove_claude_wiring_noop_when_unwired(monkeypatch, tmp_path):
    """Nothing wired -> nothing to report, no crash."""
    _patch_wiring(monkeypatch, tmp_path)
    assert cli.remove_claude_wiring() == []


def _raise_systemexit(*_a, **_k):
    raise SystemExit("Missing tenuo.yaml")


def test_teardown_cfg_recovers_name_from_state(monkeypatch, tmp_path):
    """With no valid policy, teardown still finds the container name from state.json."""
    monkeypatch.setattr(cli, "load_config", _raise_systemexit)
    state_json = tmp_path / "state.json"
    state_json.write_text(json.dumps({"name": "recovered-proj"}))
    monkeypatch.setattr(cli, "STATE_JSON", state_json, raising=False)

    assert cli._teardown_cfg()["name"] == "recovered-proj"


def test_teardown_cfg_defaults_when_no_state(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "load_config", _raise_systemexit)
    monkeypatch.setattr(cli, "STATE_JSON", tmp_path / "absent.json", raising=False)

    assert cli._teardown_cfg()["name"] == "tenuo-claude"


def test_cmd_disable_unwires_without_valid_policy(monkeypatch, tmp_path):
    """The repro from the P1 finding: a project with hooks but no tenuo.yaml must
    still be cleanable — disable removes the wiring rather than bailing."""
    _patch_wiring(monkeypatch, tmp_path)
    cli.write_claude_wiring(_make_cfg())
    settings_path = tmp_path / ".claude" / "settings.json"
    assert settings_path.exists()

    monkeypatch.setattr(cli, "load_config", _raise_systemexit)
    monkeypatch.setattr(cli, "STATE_JSON", tmp_path / "absent.json", raising=False)
    monkeypatch.setattr(cli, "_stop_authorizer", lambda _cfg: False)

    cli.cmd_disable(types.SimpleNamespace())

    assert not settings_path.exists(), "hook wiring should be gone"


def test_wiring_command_is_absolute_and_path_independent(monkeypatch, tmp_path):
    """No wiring branch may emit a bare name that depends on the runtime PATH."""
    monkeypatch.delenv("TENUO_CLAUDE_BIN", raising=False)
    # No repo launcher (PyPI layout) → falls through to the python -m branch.
    monkeypatch.setattr(cli, "LAUNCHER", tmp_path / "bin" / "tenuo-claude", raising=False)
    monkeypatch.setattr(cli, "LAUNCHER_REL", "./bin/tenuo-claude", raising=False)

    cmd, args = cli.wiring_command_parts("_hook")

    assert os.path.isabs(cmd), f"wired command must be absolute, got {cmd!r}"
    assert cmd != cli.CLI_COMMAND, "must not emit bare `tenuo-claude`"
    assert cmd == sys.executable
    assert args == ["-I", "-m", "tenuo_claude_code.cli", "_hook"]


def test_wiring_command_prefers_executable_launcher(monkeypatch, tmp_path):
    """A repo ``bin/tenuo-claude`` is used by its ABSOLUTE path, never relative."""
    monkeypatch.delenv("TENUO_CLAUDE_BIN", raising=False)
    launcher = tmp_path / "bin" / "tenuo-claude"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o755)
    monkeypatch.setattr(cli, "LAUNCHER", launcher, raising=False)

    cmd, args = cli.wiring_command_parts("_hook")

    assert cmd == str(launcher.resolve())
    assert os.path.isabs(cmd)
    assert args == ["_hook"]


def test_hook_wiring_guard_blocks_when_launcher_missing(monkeypatch, tmp_path):
    """POSIX guard: a vanished launcher must emit deny JSON and exit 2, not allow."""
    if os.name != "posix":
        pytest.skip("guard is POSIX-only")
    monkeypatch.delenv("TENUO_CLAUDE_BIN", raising=False)
    # Point the launcher at a non-existent path so the runtime `[ -x ... ]` fails.
    fake = tmp_path / "gone" / "python"
    monkeypatch.setattr(cli, "wiring_command_parts",
                        lambda sub: (str(fake), [sub]), raising=False)

    guard = cli.hook_wiring_command_string("_hook")
    proc = subprocess.run(["/bin/sh", "-c", guard], capture_output=True, text=True)

    assert proc.returncode == 2, "missing launcher must BLOCK (exit 2)"
    out = json.loads(proc.stdout)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


def test_hook_wiring_guard_execs_real_hook_when_present(monkeypatch, tmp_path):
    """POSIX guard: when the launcher IS executable, exec it (preserve stdout/exit)."""
    if os.name != "posix":
        pytest.skip("guard is POSIX-only")
    monkeypatch.delenv("TENUO_CLAUDE_BIN", raising=False)
    launcher = tmp_path / "tenuo-claude"
    launcher.write_text("#!/bin/sh\necho REAL-HOOK-RAN; exit 0\n")
    launcher.chmod(0o755)
    monkeypatch.setattr(cli, "wiring_command_parts",
                        lambda sub: (str(launcher), [sub]), raising=False)

    guard = cli.hook_wiring_command_string("_hook")
    proc = subprocess.run(["/bin/sh", "-c", guard], capture_output=True, text=True)

    assert proc.returncode == 0
    assert "REAL-HOOK-RAN" in proc.stdout


def test_root_from_warrant_issuer(monkeypatch):
    class FakeIssuer:
        def to_bytes(self):
            return bytes.fromhex("ab" * 32)

    class FakeWarrant:
        issuer = FakeIssuer()

        @staticmethod
        def from_base64(warrant_b64):
            assert warrant_b64 == "WARRANT"
            return FakeWarrant()

    monkeypatch.setitem(sys.modules, "tenuo", types.SimpleNamespace(Warrant=FakeWarrant))

    assert cli.root_from_warrant_issuer("WARRANT") == "ab" * 32
