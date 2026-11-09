"""Project state lives under ~/.tenuo, outside the governed project."""
from __future__ import annotations

from pathlib import Path

import pytest

from tenuo_claude_code import cli, paths


@pytest.fixture
def real_binding(monkeypatch, tmp_path):
    """A project bound through the real resolver, with cli's globals restored after."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "tenuo.yaml").write_text("name: t\n")
    monkeypatch.setenv("TENUO_PROJECT_DIR", str(project))
    saved = dict(vars(cli))
    yield project
    for name in set(vars(cli)) - set(saved):
        delattr(cli, name)
    vars(cli).update(saved)


def test_new_project_state_is_outside_the_project(real_binding):
    state = paths.project_state_dir(real_binding)
    assert state.parent == Path.home() / ".tenuo" / "projects"
    assert state.name.startswith("proj-")
    assert real_binding.resolve() not in state.resolve().parents


def test_two_projects_with_one_name_do_not_share_state(tmp_path):
    a, b = tmp_path / "a" / "app", tmp_path / "b" / "app"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    assert paths.project_state_dir(a) != paths.project_state_dir(b)


def test_state_dir_override(real_binding, monkeypatch, tmp_path):
    monkeypatch.setenv("TENUO_STATE_DIR", str(tmp_path / "elsewhere"))
    assert paths.project_state_dir(real_binding) == (tmp_path / "elsewhere").resolve()


def test_legacy_state_is_used_until_migrated_then_ignored(real_binding):
    legacy = real_binding / ".state"
    legacy.mkdir()
    assert paths.project_state_dir(real_binding) != legacy      # empty dir is not a state dir
    (legacy / "state.json").write_text("{}")
    assert paths.project_state_dir(real_binding) == legacy
    paths.home_state_dir(real_binding).mkdir(parents=True)
    assert paths.project_state_dir(real_binding) == paths.home_state_dir(real_binding)


def test_migrate_moves_state_and_rebinds(real_binding, capsys):
    legacy = real_binding / ".state"
    legacy.mkdir()
    (legacy / "state.json").write_text("{}")
    (legacy / "issuer_key.b64").write_text("secret")
    (legacy / "receipts.jsonl").write_text("{}\n")
    paths.bind_project_paths(cli)
    assert cli.state_in_project()

    assert cli.migrate_legacy_state() is True

    home = paths.home_state_dir(real_binding)
    assert cli.STATE == home and cli.ISSUER_KEY == home / "issuer_key.b64"
    assert not legacy.exists()
    assert (home / "issuer_key.b64").read_text() == "secret"
    assert (home / "receipts.jsonl").read_text() == "{}\n"
    assert home.stat().st_mode & 0o777 == 0o700
    assert "Moved Tenuo state out of the project" in capsys.readouterr().out
    assert cli.migrate_legacy_state() is False


def test_path_tools_cannot_reach_either_state_location(real_binding):
    paths.bind_project_paths(cli)
    cli.STATE.mkdir(parents=True)
    assert cli.tenuo_file_target("Read", {"file_path": str(cli.STATE / "issuer_key.b64")}) == "~/.tenuo state"
    assert cli.tenuo_file_target("Grep", {"pattern": "x", "path": str(cli.STATE)}) == "~/.tenuo state"
    assert cli.tenuo_file_target(
        "Read", {"file_path": str(real_binding / ".state" / "issuer_key.b64")}) == ".state"


def test_gitignore_untouched_when_state_is_outside(real_binding):
    paths.bind_project_paths(cli)
    cli._ensure_state_in_gitignore()
    assert not (real_binding / ".gitignore").exists()


def test_explicit_override_is_never_migrated(real_binding, monkeypatch):
    legacy = real_binding / ".state"
    legacy.mkdir()
    (legacy / "state.json").write_text("{}")
    (legacy / "issuer_key.b64").write_text("secret")
    monkeypatch.setenv("TENUO_STATE_DIR", str(legacy))
    paths.bind_project_paths(cli)

    assert cli.migrate_legacy_state() is False
    assert (legacy / "issuer_key.b64").read_text() == "secret"
    assert not paths.home_state_dir(real_binding).exists()


def test_grep_root_containing_state_is_denied(real_binding, monkeypatch, tmp_path):
    """Legacy layout or an in-project override: a search over the project would read keys."""
    legacy = real_binding / ".state"
    legacy.mkdir()
    (legacy / "state.json").write_text("{}")
    (real_binding / "src").mkdir()
    paths.bind_project_paths(cli)
    monkeypatch.chdir(real_binding)

    assert cli.tenuo_file_target("Grep", {"pattern": "x"}) == ".state (inside this search root)"
    assert cli.tenuo_file_target("Grep", {"pattern": "x", "path": str(real_binding)}) \
        == ".state (inside this search root)"
    assert cli.tenuo_file_target("Grep", {"pattern": "x", "path": str(tmp_path)}) is not None
    assert cli.tenuo_file_target("Grep", {"pattern": "x", "path": str(real_binding / "src")}) is None
    assert cli.tenuo_file_target("Glob", {"pattern": "*"}) is None


def test_grep_over_the_project_is_fine_once_state_is_outside(real_binding, monkeypatch):
    paths.bind_project_paths(cli)
    cli.STATE.mkdir(parents=True)
    monkeypatch.chdir(real_binding)
    assert cli.tenuo_file_target("Grep", {"pattern": "x"}) is None
    assert cli.tenuo_file_target("Grep", {"pattern": "x", "path": str(real_binding)}) is None
    assert cli.tenuo_file_target("Grep", {"pattern": "x", "path": str(Path.home())}) \
        == "~/.tenuo state (inside this search root)"


def test_long_lived_process_follows_a_moved_state(real_binding):
    legacy = real_binding / ".state"
    legacy.mkdir()
    (legacy / "state.json").write_text("{}")
    paths.bind_project_paths(cli)
    assert cli.follow_moved_state() is False

    home = paths.home_state_dir(real_binding)
    home.parent.mkdir(parents=True)
    legacy.rename(home)                      # what another process's `refresh` does
    assert cli.STATE == legacy               # this process still holds the old binding
    assert cli.follow_moved_state() is True
    assert cli.STATE == home and cli.WARRANT == home / "warrant.b64"


def test_in_project_override_is_gitignored_with_a_working_line(real_binding, monkeypatch):
    monkeypatch.setenv("TENUO_STATE_DIR", str(real_binding / "private-state"))
    paths.bind_project_paths(cli)
    assert cli.state_path_in_project() == "private-state"
    # A line the old code wrote: pattern plus trailing text, which ignores nothing.
    (real_binding / ".gitignore").write_text("private-state/  # Tenuo: private keys\n")

    cli._ensure_state_in_gitignore()
    cli._ensure_state_in_gitignore()

    lines = (real_binding / ".gitignore").read_text().splitlines()
    assert lines.count("private-state/") == 1
    assert lines[-2].startswith("#")


def test_installed_runtime_inside_the_project_is_write_protected(real_binding, monkeypatch):
    paths.bind_project_paths(cli)
    venv = real_binding / ".venv"
    pkg = venv / "lib" / "site-packages" / "tenuo_claude_code"
    pkg.mkdir(parents=True)
    monkeypatch.setattr(cli.sys, "prefix", str(venv))
    monkeypatch.setattr(cli, "PACKAGE_DIR", pkg)
    label = "the environment Tenuo runs from"
    assert cli.tenuo_file_target("Write", {"file_path": str(pkg / "cli.py")}) == label
    assert cli.tenuo_file_target("Edit", {"file_path": str(venv / "lib" / "site-packages" / "yaml.py")}) == label
    assert cli.tenuo_file_target("Read", {"file_path": str(pkg / "cli.py")}) is None
    assert cli.tenuo_file_target("Write", {"file_path": str(real_binding / "src.py")}) is None


def test_runtime_outside_the_project_is_not_special(real_binding, monkeypatch, tmp_path):
    paths.bind_project_paths(cli)
    monkeypatch.setattr(cli.sys, "prefix", str(tmp_path / "tool-venv"))
    monkeypatch.setattr(cli, "PACKAGE_DIR", tmp_path / "tool-venv" / "pkg")
    assert cli.tenuo_file_target("Write", {"file_path": str(real_binding / "a.py")}) is None
