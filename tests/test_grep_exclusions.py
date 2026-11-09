"""A recursive Grep runs with Tenuo's own project files excluded."""
from __future__ import annotations

import io
import json

import pytest

from tenuo_claude_code import cli, paths


@pytest.fixture
def project(monkeypatch, tmp_path):
    root = tmp_path / "proj"
    (root / ".claude").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "tenuo.yaml").write_text("name: t\n")
    (root / ".mcp.json").write_text("{}")
    (root / ".claude" / "settings.json").write_text("{}")
    monkeypatch.setenv("TENUO_PROJECT_DIR", str(root))
    saved = dict(vars(cli))
    paths.bind_project_paths(cli)
    monkeypatch.chdir(root)
    yield root
    for name in set(vars(cli)) - set(saved):
        delattr(cli, name)
    vars(cli).update(saved)


def test_project_root_search_excludes_existing_owned_files(project):
    tokens, problem = cli.grep_exclusions({"pattern": "x"})
    assert problem is None
    assert tokens == ["!/.claude/settings.json", "!/.mcp.json", "!/tenuo.yaml"]
    assert cli.grep_exclusions({"pattern": "x", "path": str(project)})[0] == tokens


def test_exclusions_are_relative_to_the_search_root(project):
    assert cli.grep_exclusions({"pattern": "x", "path": ".claude"}) == (["!/settings.json"], None)
    assert cli.grep_exclusions({"pattern": "x", "path": "src"}) == ([], None)
    assert cli.grep_exclusions({"pattern": "x", "path": "tenuo.yaml"}) == ([], None)   # a file, not a tree


def test_exclusion_uses_the_on_disk_spelling(project):
    (project / "tenuo.yaml").rename(project / "tenuo.tmp")
    (project / "tenuo.tmp").rename(project / "Tenuo.YAML")
    assert "!/Tenuo.YAML" in cli.grep_exclusions({"pattern": "x"})[0]


def test_callers_glob_comes_first_and_exclusions_last(project):
    tin = {"pattern": "x", "glob": "*.{md,yaml}", "output_mode": "content"}
    tokens, problem = cli.grep_exclusions(tin)
    assert problem is None
    new = cli.grep_input_with_exclusions(tin, tokens)
    assert new["glob"] == "*.{md,yaml} !/.claude/settings.json !/.mcp.json !/tenuo.yaml"
    assert new["pattern"] == "x" and new["output_mode"] == "content"
    assert cli.grep_input_with_exclusions({"pattern": "x"}, tokens)["glob"] == " ".join(tokens)


@pytest.mark.parametrize("glob", ["{a, b}", "*.py }", "{{a}"])
def test_glob_that_cannot_be_combined_is_refused(project, glob):
    tokens, problem = cli.grep_exclusions({"pattern": "x", "glob": glob})
    assert tokens == [] and "glob" in problem


def test_unexcludable_path_is_refused(monkeypatch, tmp_path):
    root = tmp_path / "my proj"
    root.mkdir()
    (root / "tenuo.yaml").write_text("name: t\n")
    monkeypatch.setenv("TENUO_PROJECT_DIR", str(root))
    saved = dict(vars(cli))
    try:
        paths.bind_project_paths(cli)
        tokens, problem = cli.grep_exclusions({"pattern": "x", "path": str(tmp_path)})
        assert tokens == [] and "narrower" in problem
        assert cli.grep_exclusions({"pattern": "x", "path": str(root)}) == (["!/tenuo.yaml"], None)
    finally:
        for name in set(vars(cli)) - set(saved):
            delattr(cli, name)
        vars(cli).update(saved)


def _run_hook(monkeypatch, capsys, tin, *, allowed=True, mode="enforce"):
    receipts = []
    monkeypatch.setattr(cli, "load_config", lambda: {"mode": mode})
    monkeypatch.setattr(cli, "apply_transport_env", lambda cfg: None)
    monkeypatch.setattr(cli, "is_audit_mode", lambda cfg: mode != "enforce")
    monkeypatch.setattr(cli, "subagent_roles", lambda cfg: {})
    monkeypatch.setattr(cli, "authorize_call",
                        lambda *a, **k: (allowed, "authorized" if allowed else "no", True, "grep", {"e": 1}))
    monkeypatch.setattr(cli, "write_receipt", lambda r: receipts.append(r) or True)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "Grep", "tool_input": tin})))
    cli.cmd_hook(None)
    out = capsys.readouterr().out
    return (json.loads(out)["hookSpecificOutput"] if out.strip() else None), receipts[-1]


def test_hook_allows_grep_with_rewritten_input(project, monkeypatch, capsys):
    out, receipt = _run_hook(monkeypatch, capsys, {"pattern": "x", "glob": "*.json"})
    assert out["permissionDecision"] == "allow"
    assert out["updatedInput"] == {
        "pattern": "x", "glob": "*.json !/.claude/settings.json !/.mcp.json !/tenuo.yaml"}
    assert receipt["excluded"] == ["!/.claude/settings.json", "!/.mcp.json", "!/tenuo.yaml"]
    assert receipt["args"] == {"pattern": "x", "glob": "*.json"}      # what the model asked for


def test_hook_leaves_unaffected_grep_alone(project, monkeypatch, capsys):
    out, receipt = _run_hook(monkeypatch, capsys, {"pattern": "x", "path": "src"})
    assert out["permissionDecision"] == "allow" and "updatedInput" not in out
    assert "excluded" not in receipt


def test_hook_denies_grep_it_cannot_filter(project, monkeypatch, capsys):
    out, receipt = _run_hook(monkeypatch, capsys, {"pattern": "x", "glob": "{a, b}"})
    assert out["permissionDecision"] == "deny" and "updatedInput" not in out
    assert receipt["decision"] == "deny" and receipt["authz"] == {}


def test_hook_never_rewrites_a_denied_or_dry_run_call(project, monkeypatch, capsys):
    out, _ = _run_hook(monkeypatch, capsys, {"pattern": "x"}, allowed=False)
    assert out["permissionDecision"] == "deny" and "updatedInput" not in out
    out, receipt = _run_hook(monkeypatch, capsys, {"pattern": "x"}, mode="dry-run")
    assert out is None                                   # observe-only stays neutral
    assert receipt["excluded"]                           # but records what enforce would exclude
