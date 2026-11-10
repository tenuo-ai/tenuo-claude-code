"""Invocation identity must survive routing, compilation, PoP and approval hashing."""
import json

import pytest
from tenuo import SigningKey
from tenuo_core import py_compute_request_hash
from tenuo_claude_code import admin, cli


def github_cfg(make_cfg):
    return make_cfg(mcp={"server": "github", "enforce": {"merge_pull_request": {
        "args": {"owner": "exact:myorg", "repo": "exact:service"},
        "approval": {"threshold": 1}}}})


def test_approval_hash_covers_unconstrained_arguments(make_cfg):
    cfg = github_cfg(make_cfg)
    holder = SigningKey.generate()
    def request(number):
        tin = {"owner": "myorg", "repo": "service", "pullNumber": number}
        cap, _, args, _, _ = cli.resolve_tool(cfg, "mcp__github__merge_pull_request", tin)
        return py_compute_request_hash("w1", cap, args, holder.public_key)
    assert request(1) != request(999)


def test_catchall_approval_binds_all_arguments_and_tool(make_cfg):
    holder = SigningKey.generate()
    cfg = make_cfg(default="approve")
    def request(tool, args):
        cap, _, signed, _, _ = cli.resolve_tool(cfg, tool, args)
        return py_compute_request_hash("w1", cap, signed, holder.public_key)
    assert request("unknown", {"operation": "read"}) != request("unknown", {"operation": "delete"})
    assert request("unknown", {"a": 1, "b": 2}) == request("unknown", {"b": 2, "a": 1})
    assert request("unknown", {}) != request("other", {})


def test_mcp_server_identity_and_native_capabilities_are_distinct(make_cfg):
    cfg = make_cfg(enforce={"Read": "subpath:/safe"},
        mcp={"server": "files", "enforce": {"read_file": "subpath:/other"}})
    assert cli.resolve_tool(cfg, "Read", {"file_path": "/safe/a"})[0] == "read_file"
    assert cli.resolve_tool(cfg, "mcp__files__read_file", {"path": "/other/a"})[0] == "mcp__files__read_file"
    assert cli.resolve_tool(cfg, "mcp__attacker__read_file", {"path": "/other/a"})[0] == "unlisted"
    caps = cli.enforced_capabilities(cfg)
    assert "read_file" in caps and "mcp__files__read_file" in caps


def test_local_gated_mcp_is_not_granted_without_cloud(make_cfg, monkeypatch):
    cfg = github_cfg(make_cfg)
    monkeypatch.setattr(cli, "use_cloud_trigger", lambda cfg: False)
    assert "mcp__github__merge_pull_request" not in cli.enforced_capabilities(cfg)


def test_gateway_cloud_and_router_agree_on_bound_fields(make_cfg, bound, monkeypatch):
    import yaml
    cfg = github_cfg(make_cfg)
    cap, route, args, body, _ = cli.resolve_tool(cfg, "mcp__github__merge_pull_request",
        {"owner": "myorg", "repo": "service", "pullNumber": 42})
    monkeypatch.setattr(cli, "sync_authorizer_mount", lambda: None)
    cli.STATE.mkdir()
    cli.write_gateway(cfg, {})
    gateway = yaml.safe_load(cli.GATEWAY.read_text())
    fields = next(r["constraints"] for r in gateway["routes"] if r["pattern"] == route)
    cloud = admin.build_warrant_config(cfg, "approval-policy")
    assert set(fields) == set(args) == set(cloud["per_action_constraints"][cap])
    assert body == args
    assert json.loads(args[cli.REQUEST_FIELD])["arguments"]["pullNumber"] == 42


def test_reserved_input_cannot_replace_binding(make_cfg):
    cfg = make_cfg(enforce={"Write": "subpath:/safe"})
    tin = {"file_path": "/safe/a", "content": "new", cli.REQUEST_FIELD: "forged"}
    args = cli.resolve_tool(cfg, "Write", tin)[2]
    assert args[cli.REQUEST_FIELD] != "forged"
    assert json.loads(args[cli.REQUEST_FIELD])["arguments"] == tin
