from __future__ import annotations

import argparse

import pytest
import yaml

from tenuo_claude_code import admin, packs


SAMPLE_PARAMS = {
    "filesystem-dev": {
        "sandbox": "./workspace",
        "web_domain": "api.github.com",
    },
    "github-mcp": {
        "repos": "myorg/payments-api",
        "approver": "niki@tenuo.ai",
    },
    "http-api-safe": {
        "tool": "http_call",
        "url_arg": "url",
        "method_arg": "method",
        "url_pattern": "https://api.acme.com/v1/*",
        "methods": "GET,HEAD",
    },
}


def _bind_load_config_paths(monkeypatch, cli_mod, tmp_path):
    monkeypatch.setattr(cli_mod, "CONFIG_FILE", tmp_path / "tenuo.yaml", raising=False)
    monkeypatch.setattr(cli_mod, "CLOUD_PROFILE", tmp_path / "tenuo.cloud.yaml", raising=False)
    monkeypatch.setattr(cli_mod, "ADVANCED_PROFILE", tmp_path / "tenuo.advanced.yaml", raising=False)
    monkeypatch.setattr(cli_mod, "HARNESS_TOOLS_FILE", tmp_path / "harness_tools.yaml", raising=False)
    monkeypatch.setattr(cli_mod, "CLOUD_STATE", tmp_path / ".state" / "cloud_state.json", raising=False)


def test_expected_bundled_packs_are_present():
    names = {p.name for p in packs.list_packs()}
    assert {
        "filesystem-dev",
        "github-mcp",
        "http-api-safe",
    } == names


def test_load_pack_rejects_missing_required_metadata(monkeypatch, tmp_path):
    (tmp_path / "pack.yaml").write_text(
        """
name: broken
version: 1
reviewed: "2026-07-10"
reviewed_by: tenuo-packs
""",
        encoding="utf-8",
    )
    (tmp_path / "tenuo.yaml.tmpl").write_text("name: demo\n", encoding="utf-8")
    monkeypatch.setattr(packs, "_pack_dir", lambda name: tmp_path)

    with pytest.raises(SystemExit, match="missing required field 'pinned'"):
        packs.load_pack("broken")


def test_load_pack_requires_template(monkeypatch, tmp_path):
    (tmp_path / "pack.yaml").write_text(
        """
name: missing-template
version: 1
reviewed: "2026-07-10"
reviewed_by: tenuo-packs
pinned:
  name: tool-surface
  version: "1"
  tool_list_hash: abc123
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(packs, "_pack_dir", lambda name: tmp_path)

    with pytest.raises(SystemExit, match="missing required file 'tenuo.yaml.tmpl'"):
        packs.load_pack("missing-template")


def test_all_bundled_packs_render_and_load(monkeypatch, tmp_path, cli_mod, bound):
    _bind_load_config_paths(monkeypatch, cli_mod, tmp_path)
    for pack in packs.list_packs():
        text = packs.render_pack(pack, SAMPLE_PARAMS[pack.name])
        data = yaml.safe_load(text)
        assert data["mode"] == "dry-run"
        assert data["default"] == "deny"
        cli_mod.CONFIG_FILE.write_text(text)
        cfg = cli_mod.load_config()
        assert cfg["name"]


def test_github_mcp_pack_renders_policy():
    pack = packs.load_pack("github-mcp")

    text = packs.render_pack(
        pack,
        {"repos": "myorg/payments-api", "approver": "niki@tenuo.ai"},
    )
    data = yaml.safe_load(text)

    assert data["name"] == "github-agent"
    assert data["mode"] == "dry-run"
    assert data["default"] == "deny"
    assert data["mcp"]["enforce"]["get_file_contents"]["constraint"] == "pattern:myorg/payments-api"
    merge = data["mcp"]["enforce"]["merge_pull_request"]
    assert merge["args"]["repo"] == "pattern:myorg/payments-api"
    assert merge["approval"] == {"threshold": 1, "approver": "niki@tenuo.ai"}
    assert data["deny"] == ["delete_repository", "delete_branch", "fork_repository"]


def test_init_pack_writes_policy_and_compiles(monkeypatch, tmp_path, cli_mod, bound):
    _bind_load_config_paths(monkeypatch, cli_mod, tmp_path)
    called = {}

    def fake_generate(cfg):
        called["cfg"] = cfg
        return {"warrant_id": "w_123", "sandbox": cfg["_sandbox_abs"]}

    monkeypatch.setattr(cli_mod, "generate", fake_generate)

    cli_mod.cmd_init(argparse.Namespace(
        pack="github-mcp",
        param=["repos=myorg/payments-api", "approver=niki@tenuo.ai"],
        force=False,
        scaffold=False,
        local=False,
        cloud=False,
        advanced=False,
        demo=False,
    ))

    text = (tmp_path / "tenuo.yaml").read_text()
    assert "# pack: github-mcp v3" in text
    assert "pattern:myorg/payments-api" in text
    assert called["cfg"]["mcp"]["enforce"]["merge_pull_request"]["approval"]["approver"] == "niki@tenuo.ai"


def test_cloud_warrant_config_keeps_constraints_and_approval_gate(make_cfg):
    cfg = make_cfg(
        mcp={
            "enforce": {
                "merge_pull_request": {
                    "args": {"repo": "pattern:myorg/payments-api"},
                    "approval": {"threshold": 1, "approver": "niki@tenuo.ai"},
                }
            }
        }
    )

    wc = admin.build_warrant_config(cfg, approval_policy_id="appr_123")

    assert wc["per_action_constraints"]["merge_pull_request"] == {
        "repo": {"_type": "pattern", "_value": "myorg/payments-api"}
    }
    assert wc["approval_gates"]["merge_pull_request"] == {"args": None}
    assert wc["approval_gates"]["_policy_id"] == "appr_123"


def test_bootstrap_pack_renders_policy_without_prompting(monkeypatch, tmp_path, cli_mod, bound):
    """`bootstrap --pack` (the README quickstart) renders the pack with defaults."""
    _bind_load_config_paths(monkeypatch, cli_mod, tmp_path)
    steps = []
    monkeypatch.setattr(cli_mod, "cmd_init", lambda args: steps.append("init"))
    monkeypatch.setattr(cli_mod, "cmd_up", lambda args: steps.append("up"))
    monkeypatch.setattr(cli_mod, "cmd_verify", lambda args: steps.append("verify"))
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("bootstrap must not prompt"))

    cli_mod.cmd_bootstrap(argparse.Namespace(pack="filesystem-dev", native=False, install=False))

    assert "# pack: filesystem-dev" in (tmp_path / "tenuo.yaml").read_text()
    assert steps == ["init", "up", "verify"]
