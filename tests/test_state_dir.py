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
