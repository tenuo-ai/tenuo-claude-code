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


@pytest.mark.parametrize("external", [False, True])
def test_runtime_directory_links_must_stay_inside_environment(tmp_path, monkeypatch, external):
    env = tmp_path / "venv"
    (env / "bin").mkdir(parents=True)
    (env / "lib").mkdir()
    (env / "pyvenv.cfg").write_text("home = /usr/bin")
    (env / "bin/python").write_text("fake")
    (env / "lib64").symlink_to(tmp_path if external else env / "lib", target_is_directory=True)
    checked = []
    monkeypatch.setattr(managed_runtime, "_trusted_path", checked.append)
    if external:
        with pytest.raises(SystemExit, match="Untrusted managed hook runtime"):
            managed_runtime.validate_managed_python(str(env / "bin/python"))
    else:
        assert managed_runtime.validate_managed_python(str(env / "bin/python")) == str(env / "bin/python")
        assert env / "lib64" in checked


@pytest.mark.parametrize('kind', ['external', 'editable', 'executable', 'system', 'internal'])
def test_managed_import_paths(kind, tmp_path, monkeypatch):
    env = tmp_path / 'venv'
    (env / 'bin').mkdir(parents=True)
    site = env / 'lib/python3.12/site-packages'
    site.mkdir(parents=True)
    (env / 'bin/python').write_text('fake')
    (env / 'pyvenv.cfg').write_text('include-system-site-packages = ' + ('true' if kind == 'system' else 'false'))
    monkeypatch.setattr(managed_runtime, '_trusted_path', lambda path: None)
    if kind == 'external':
        (site / 'project.pth').write_text(str(tmp_path))
    elif kind == 'editable':
        (site / 'project.egg-link').write_text(str(tmp_path))
    elif kind == 'executable':
        (site / 'project.pth').write_text('import sys; sys.path.insert(0, "/developer/checkout")')
    elif kind == 'internal':
        (site / 'vendor').mkdir()
        (site / 'vendor.pth').write_text('# trusted internal package\nvendor\n')
    if kind == 'internal':
        assert managed_runtime.validate_managed_python(str(env / 'bin/python')) == str(env / 'bin/python')
    else:
        with pytest.raises(SystemExit, match='Untrusted managed hook runtime'):
            managed_runtime.validate_managed_python(str(env / 'bin/python'))
