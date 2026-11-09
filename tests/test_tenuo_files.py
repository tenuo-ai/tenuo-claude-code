"""Path tools never reach Tenuo's own keys, policy or hook wiring."""
from __future__ import annotations

import os

import pytest


@pytest.fixture
def project(bound):
    (bound / ".state").mkdir()
    (bound / ".state" / "issuer_key.b64").write_text("secret")
    (bound / "src").mkdir()
    return bound


@pytest.mark.parametrize("tool,field,rel,owned", [
    ("Read", "file_path", ".state/issuer_key.b64", ".state"),
    ("Grep", "path", ".state", ".state"),
    ("Write", "file_path", "tenuo.yaml", "tenuo.yaml"),
    ("Edit", "file_path", ".claude/settings.json", ".claude/settings.json"),
    ("Edit", "file_path", ".claude/settings.local.json", ".claude/settings.local.json"),
    ("Write", "file_path", ".mcp.json", ".mcp.json"),
    ("Read", "file_path", "src/app.py", None),
    ("Edit", "file_path", ".claude/agents/reviewer.md", None),
])
def test_tenuo_file_target(cli_mod, project, tool, field, rel, owned):
    assert cli_mod.tenuo_file_target(tool, {field: str(project / rel)}) == owned


def test_symlink_into_state_is_caught(cli_mod, project):
    link = project / "src" / "key.txt"
    os.symlink(project / ".state" / "issuer_key.b64", link)
    assert cli_mod.tenuo_file_target("Read", {"file_path": str(link)}) == ".state"


def test_non_path_tools_are_not_checked(cli_mod, project):
    assert cli_mod.tenuo_file_target("Bash", {"command": "cat .state/issuer_key.b64"}) is None
    assert cli_mod.tenuo_file_target("Grep", {"pattern": "x"}) is None


def test_authorize_call_denies_before_the_authorizer(cli_mod, project, make_cfg, monkeypatch):
    monkeypatch.setattr(cli_mod, "authorize", lambda *a, **k: pytest.fail("must not reach the authorizer"))
    allowed, reason, governed, tool = cli_mod.authorize_call(
        make_cfg(), "Read", {"file_path": str(project / ".state" / "issuer_key.b64")}, None, {})
    assert (allowed, governed, tool) == (False, True, "Read")
    assert reason.startswith(".state is Tenuo's own file")
