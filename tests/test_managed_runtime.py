"""Managed templates must reject writable runtime installations."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from tenuo_claude_code import cli, managed_runtime


def test_user_owned_runtime_is_rejected(tmp_path):
    env = tmp_path / "venv"
    (env / "bin").mkdir(parents=True)
    (env / "pyvenv.cfg").write_text("home = /usr/bin")
    (env / "bin/python").write_text("fake")
    with pytest.raises(SystemExit, match="Untrusted managed hook runtime"):
        managed_runtime.validate_managed_python(str(env / "bin/python"))


def test_writable_ancestor_is_rejected(monkeypatch):
    def stat(path, *a, **kw):
        return SimpleNamespace(st_uid=0, st_mode=0o40777 if str(path) == "/opt" else 0o100755)
    monkeypatch.setattr(Path, "stat", stat)
    monkeypatch.setattr(Path, "resolve", lambda self, **kw: self)
    with pytest.raises(ValueError, match="/opt must be root-owned"):
        managed_runtime._trusted_path(Path("/opt/venv/bin/python"))


def test_managed_launcher_ignores_project_override(monkeypatch):
    monkeypatch.setenv("TENUO_CLAUDE_BIN", "/project/evil")
    monkeypatch.setattr(managed_runtime, "validate_managed_python", lambda p: "/opt/tenuo/venv/bin/python")
    command, args = cli.managed_command_parts({}, "_managed-hook")
    assert command == "/opt/tenuo/venv/bin/python"
    assert args == ["-I", "-m", "tenuo_claude_code.cli", "_managed-hook"]
