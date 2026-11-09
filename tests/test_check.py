"""Preflight / wiring checks (PyPI layout — no repo ``bin/tenuo-claude``)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

import pytest

from tenuo_claude_code import cli
from tenuo_claude_code import __version__


def test_check_wiring_ok_without_launcher(monkeypatch, tmp_path):
    """Missing ``./bin/tenuo-claude`` must not fail preflight (PyPI installs use PATH)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setattr(cli, "LAUNCHER", proj / "bin" / "tenuo-claude", raising=False)
    monkeypatch.setattr(cli, "DEMO_DIR", proj, raising=False)
    ok = cli._check_wiring({"mcp": {}}, True)
    assert ok is True


def test_cli_version_works_without_project(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "tenuo_claude_code.cli", "--version"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0
    assert f"tenuo-claude-code {__version__}" in proc.stdout


@pytest.mark.parametrize("args", [["--help"], ["setup", "--help"]])
def test_admin_help_works_without_project(tmp_path, args):
    proc = subprocess.run(
        [sys.executable, "-m", "tenuo_claude_code.admin", *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0
    assert "usage: tenuo-admin" in proc.stdout


def _write_pre_hook(proj, command: str) -> None:
    """Write a .claude/settings.json with a single PreToolUse hook command."""
    claude = proj / ".claude"
    claude.mkdir(parents=True, exist_ok=True)
    settings = {"hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]}]}}
    (claude / "settings.json").write_text(json.dumps(settings))


def test_check_flags_bare_path_dependent_hook_command(monkeypatch, tmp_path):
    """A bare `tenuo-claude` wired command must be a CHECK FAILURE, not a no-op.

    A bare name resolves only via the launching shell's PATH; if Claude's shell
    lacks the venv, the hook never runs and tools proceed ungoverned.
    """
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setattr(cli, "LAUNCHER", proj / "bin" / "tenuo-claude", raising=False)
    monkeypatch.setattr(cli, "DEMO_DIR", proj, raising=False)
    # Force the wired command to a bare name so the comparison and resolver both
    # see PATH-dependent wiring.
    monkeypatch.setattr(cli, "hook_wiring_command_string",
                        lambda sub: "tenuo-claude _hook", raising=False)
    _write_pre_hook(proj, "tenuo-claude _hook")

    ok = cli._check_wiring({"mcp": {}}, True)
    assert ok is False, "bare PATH-dependent hook command must fail check"


def test_check_flags_unresolvable_absolute_hook_command(monkeypatch, tmp_path):
    """An absolute launcher that no longer exists must fail check."""
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setattr(cli, "LAUNCHER", proj / "bin" / "tenuo-claude", raising=False)
    monkeypatch.setattr(cli, "DEMO_DIR", proj, raising=False)
    gone = proj / "gone" / "tenuo-claude"
    monkeypatch.setattr(cli, "hook_wiring_command_string",
                        lambda sub: f"{gone} _hook", raising=False)
    _write_pre_hook(proj, f"{gone} _hook")

    ok = cli._check_wiring({"mcp": {}}, True)
    assert ok is False, "unresolvable absolute launcher must fail check"


def test_check_passes_resolvable_absolute_hook_command(monkeypatch, tmp_path):
    """An absolute, executable launcher in the wired command passes check."""
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setattr(cli, "LAUNCHER", proj / "bin" / "tenuo-claude", raising=False)
    monkeypatch.setattr(cli, "DEMO_DIR", proj, raising=False)
    launcher = proj / "tenuo-claude"
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o755)
    command = f"{launcher} _hook"
    monkeypatch.setattr(cli, "hook_wiring_command_string",
                        lambda sub: command, raising=False)
    _write_pre_hook(proj, command)

    ok = cli._check_wiring({"mcp": {}}, True)
    assert ok is True


def test_check_passes_when_tenuo_hook_is_not_first(monkeypatch, tmp_path):
    """User hooks before Tenuo should not make preflight report stale wiring."""
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setattr(cli, "LAUNCHER", proj / "bin" / "tenuo-claude", raising=False)
    monkeypatch.setattr(cli, "DEMO_DIR", proj, raising=False)
    launcher = proj / "tenuo-claude"
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o755)
    command = f"{launcher} _hook"
    monkeypatch.setattr(cli, "hook_wiring_command_string",
                        lambda sub: command, raising=False)
    claude = proj / ".claude"
    claude.mkdir(parents=True)
    settings = {"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user-hook"}]},
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    ]}}
    (claude / "settings.json").write_text(json.dumps(settings))

    ok = cli._check_wiring({"mcp": {}}, True)
    assert ok is True


def test_hook_launcher_resolves_unwraps_posix_guard(tmp_path):
    """The resolver unwraps the `/bin/sh -c` guard and probes the exec target."""
    if os.name != "posix":
        pytest.skip("guard is POSIX-only")
    launcher = tmp_path / "py"
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o755)
    sh_cmd = (f"/bin/sh -c 'if [ -x {launcher} ]; then exec {launcher} _hook; "
              f"else printf x; exit 2; fi'")
    ok, detail = cli._hook_launcher_resolves(sh_cmd)
    assert ok is True, detail
    assert str(launcher) in detail


def test_probe_runtime_creds_accepts_tenant_without_srl(monkeypatch):
    monkeypatch.setattr(
        cli,
        "cloud_api",
        lambda method, url, key, path: (
            404,
            {"error": {"code": "srl_not_found", "message": "no SRL exists for this tenant"}},
        ),
    )

    ok, msg = cli.probe_runtime_creds({"url": "https://api.example", "api_key": "rt"})

    assert ok is True
    assert "no SRL yet" in msg


def test_cloud_onboard_writes_profile_before_preflight(monkeypatch, tmp_path):
    state = tmp_path / ".state"
    monkeypatch.setattr(cli, "DEMO_DIR", tmp_path, raising=False)
    monkeypatch.setattr(cli, "STATE", state, raising=False)
    monkeypatch.setattr(cli, "CONFIG_FILE", tmp_path / "tenuo.yaml", raising=False)
    monkeypatch.setattr(cli, "CLOUD_ENV", state / "cloud.env", raising=False)
    monkeypatch.setattr(cli, "CLOUD_STATE", state / "cloud_state.json", raising=False)
    monkeypatch.setattr(cli, "CLOUD_PROFILE", tmp_path / "tenuo.cloud.yaml", raising=False)
    monkeypatch.setattr(cli, "ADVANCED_PROFILE", tmp_path / "tenuo.advanced.yaml", raising=False)
    monkeypatch.setattr(cli, "ADMIN_ENV", tmp_path / "home" / ".tenuo" / "admin.env", raising=False)
    monkeypatch.setattr(cli, "scaffold_example_policy", lambda *a, **k: False)
    monkeypatch.setattr(cli, "_parse_connect_token",
                        lambda token: {"url": "https://api.example", "api_key": "rt"})

    seen = {}

    def fake_check(_args):
        seen["mode"] = cli.intended_mode({})
        raise SystemExit(0)

    monkeypatch.setattr(cli, "cmd_check", fake_check)
    monkeypatch.setattr(cli, "cmd_init", lambda _args: None)
    monkeypatch.setattr(cli, "cmd_up", lambda _args: None)
    monkeypatch.setattr(cli, "cmd_verify", lambda _args: None)

    cli.cmd_onboard(argparse.Namespace(
        cloud=True,
        local=False,
        yes=True,
        no_scaffold=False,
        connect_token="tenuo_ct_fake",
        admin_key=None,
        advanced=False,
        demo=False,
        approver=None,
        approver_id=None,
    ))

    assert seen["mode"] == "cloud"


def test_cloud_bootstrap_missing_token_does_not_scaffold(monkeypatch, tmp_path):
    state = tmp_path / ".state"
    monkeypatch.delenv("TENUO_CONNECT_TOKEN", raising=False)
    monkeypatch.delenv("TENUO_ADMIN_KEY", raising=False)
    monkeypatch.setattr(cli, "DEMO_DIR", tmp_path, raising=False)
    monkeypatch.setattr(cli, "STATE", state, raising=False)
    monkeypatch.setattr(cli, "CONFIG_FILE", tmp_path / "tenuo.yaml", raising=False)
    monkeypatch.setattr(cli, "CLOUD_ENV", state / "cloud.env", raising=False)
    monkeypatch.setattr(cli, "ADMIN_ENV", tmp_path / "home" / ".tenuo" / "admin.env", raising=False)
    monkeypatch.setattr(cli, "_bootstrap_needs_native_install", lambda args: False)

    with pytest.raises(SystemExit, match="TENUO_CONNECT_TOKEN"):
        cli.cmd_bootstrap(argparse.Namespace(
            cloud=True,
            yes=True,
            no_scaffold=False,
            advanced=False,
            demo=False,
            connect_token=None,
            admin_key=None,
            approver=None,
            approver_id=None,
        ))

    assert not (tmp_path / "tenuo.yaml").exists()
    assert not (tmp_path / "workspace").exists()
