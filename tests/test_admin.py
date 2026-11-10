"""Tests for Cloud admin setup helpers."""

from __future__ import annotations

import pytest

from tenuo_claude_code import admin


def test_to_wire_constraint_new_kinds():
    # New kinds must match the trigger API schema (tenuo-cloud fire.go):
    # not_one_of -> excluded list, url_pattern -> string, range -> "min..max" string.
    assert admin.to_wire_constraint("notoneof:rm,curl", "/sb") == {
        "_type": "not_one_of", "_value": ["rm", "curl"],
    }
    assert admin.to_wire_constraint("urlpattern:https://api.github.com/repos/*", "/sb") == {
        "_type": "url_pattern", "_value": "https://api.github.com/repos/*",
    }
    assert admin.to_wire_constraint("cidr:10.0.0.0/8", "/sb") == {
        "_type": "cidr", "_value": "10.0.0.0/8",
    }
    assert admin.to_wire_constraint("range:1,10", "/sb") == {
        "_type": "range", "_value": "1..10",
    }
    # Open-ended bounds keep the separator so the server reads one-sided ranges.
    assert admin.to_wire_constraint("range:5,", "/sb") == {"_type": "range", "_value": "5.."}
    assert admin.to_wire_constraint("range:,100", "/sb") == {"_type": "range", "_value": "..100"}


def test_to_wire_constraint_range_rejects_invalid_specs():
    # Cloud must refuse the same specs local mint refuses, instead of silently
    # emitting ".." (match-all) or "5.." for a one-sided/no-comma input.
    with pytest.raises(SystemExit, match="at least one bound"):
        admin.to_wire_constraint("range:,", "/sb")     # blank both -> match-all
    with pytest.raises(SystemExit, match="min,max"):
        admin.to_wire_constraint("range:5", "/sb")      # no comma


def test_web_to_wire_cidrs_and_domains():
    # cidrs join domains as host members; url_safe permits private ranges.
    wire = admin.web_to_wire({"domains": ["api.github.com"], "cidrs": ["10.0.0.0/8"]})
    host_members = wire["host"]["_value"]
    assert {"_type": "pattern", "_value": "api.github.com"} in host_members
    assert {"_type": "cidr", "_value": "10.0.0.0/8"} in host_members
    assert wire["url"]["_value"]["block_private"] is False         # cidrs present
    assert wire["url"]["_value"]["allow_domains"] == ["api.github.com"]


def test_web_to_wire_cidrs_only():
    # A cidrs-only policy is now valid on Cloud (was a hard error before).
    wire = admin.web_to_wire({"cidrs": ["192.168.0.0/16"]})
    assert wire["host"]["_value"] == [{"_type": "cidr", "_value": "192.168.0.0/16"}]
    # No domain allowlist -> explicit null (host Cidr carries the allowlist).
    assert wire["url"]["_value"]["allow_domains"] is None


def test_web_to_wire_requires_domain_or_cidr():
    with pytest.raises(SystemExit, match="domain or cidr"):
        admin.web_to_wire({})


def test_web_to_wire_ports():
    # ports reach the Cloud warrant as UrlSafe.allow_ports (tenuo-core honours it,
    # mirroring local make_web_constraints); absent when unset = any port.
    with_ports = admin.web_to_wire({"domains": ["api.github.com"], "ports": [443, 8443]})
    assert with_ports["url"]["_value"]["allow_ports"] == [443, 8443]
    assert "allow_ports" not in admin.web_to_wire({"domains": ["api.github.com"]})["url"]["_value"]
    # Malformed ports fail closed on the Cloud path too (shared validator).
    with pytest.raises(SystemExit, match="must be integers"):
        admin.web_to_wire({"domains": ["api.github.com"], "ports": ["nope"]})


def test_build_warrant_config_mcp_named_and_multi_arg():
    """Named-arg / multi-arg MCP constraints serialize to per-arg Cloud wire,
    keeping local and Cloud warrants at parity for arbitrary MCP tools."""
    cfg = {
        "_sandbox_abs": "/sandbox",
        "enforce": {},
        "mcp": {"enforce": {
            "run_query": {"arg": "sql", "constraint": "regex:^SELECT"},
            "http_call": {"args": {
                "url": "urlpattern:https://api.example.com/*",
                "method": "oneof:GET,HEAD",
            }},
        }},
        "default": "deny",
        "audit": [],
    }
    wc = admin.build_warrant_config(cfg, None)
    pac = wc["per_action_constraints"]
    assert pac["mcp__tenuo-files__run_query"] == {"__tenuo_request": {"_type": "wildcard"}, "sql": {"_type": "regex", "_value": "^SELECT"}}
    assert pac["mcp__tenuo-files__http_call"] == {
        "__tenuo_request": {"_type": "wildcard"},
        "url": {"_type": "url_pattern", "_value": "https://api.example.com/*"},
        "method": {"_type": "one_of", "_value": ["GET", "HEAD"]},
    }


def test_build_warrant_config_command_exec_tools():
    """PowerShell/Monitor serialize to their own Cloud actions with the command
    constraint, so the local and Cloud warrants stay at parity."""
    cfg = {
        "_sandbox_abs": "/sandbox",
        "enforce": {
            "Bash": "shlex:ls,echo",
            "PowerShell": "oneof:Get-ChildItem",
            "Monitor": "shlex:tail",
        },
        "mcp": {},
        "default": "deny",
        "audit": [],
    }
    wc = admin.build_warrant_config(cfg, None)
    pac = wc["per_action_constraints"]
    assert {"run_command", "run_powershell", "run_monitor"} <= set(wc["actions"])
    assert pac["run_powershell"] == {"__tenuo_request": {"_type": "wildcard"}, "command": {"_type": "one_of", "_value": ["Get-ChildItem"]}}
    assert pac["run_monitor"]["command"]["_type"] == "shlex"
    assert pac["run_command"]["command"]["_type"] == "shlex"


def test_build_warrant_config_ttl_defaults_to_3600():
    """Absent `ttl_seconds` -> the Cloud trigger warrant keeps the 1h default."""
    cfg = {"_sandbox_abs": "/sandbox", "enforce": {}, "mcp": {}, "default": "deny", "audit": []}
    wc = admin.build_warrant_config(cfg, None)
    assert wc["ttl"] == 3600


def test_build_warrant_config_ttl_uses_configured_value():
    """A configured `ttl_seconds` flows through to the Cloud warrant config."""
    cfg = {"_sandbox_abs": "/sandbox", "enforce": {}, "mcp": {},
           "default": "deny", "audit": [], "ttl_seconds": 900}
    wc = admin.build_warrant_config(cfg, None)
    assert wc["ttl"] == 900


def test_resolve_approver_identity_by_id(monkeypatch):
    def fake_cloud_api(method, url, api_key, path, body=None):
        assert (method, path) == ("GET", "/v1/identities")
        return 200, {
            "identities": [
                {"id": "idn_1", "display_name": "Alice Example", "public_key": "pub1"},
                {"id": "idn_2", "display_name": "Alice Example", "public_key": "pub2"},
            ],
        }

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    assert admin.resolve_approver_identity(
        "https://api.example", "admin", "idn_2", by_id=True
    ) == ("idn_2", "Alice Example", "pub2")


def test_resolve_approver_identity_by_display_name(monkeypatch):
    def fake_cloud_api(method, url, api_key, path, body=None):
        assert (method, path) == ("GET", "/v1/identities")
        return 200, {
            "identities": [
                {"id": "idn_1", "display_name": "Alice Example", "public_key": "pub1"},
            ],
        }

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    assert admin.resolve_approver_identity(
        "https://api.example", "admin", "Alice Example"
    ) == ("idn_1", "Alice Example", "pub1")


def test_resolve_approver_identity_rejects_duplicate_display_name(monkeypatch):
    def fake_cloud_api(method, url, api_key, path, body=None):
        assert (method, path) == ("GET", "/v1/identities")
        return 200, {
            "identities": [
                {"id": "idn_1", "display_name": "Alice Example", "public_key": "pub1"},
                {"id": "idn_2", "display_name": "Alice Example", "public_key": "pub2"},
            ],
        }

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    with pytest.raises(SystemExit, match="approver_identity_id"):
        admin.resolve_approver_identity("https://api.example", "admin", "Alice Example")


def test_ensure_agent_trigger_binding_patches_stale_allowed_trigger(monkeypatch):
    calls = []

    def fake_cloud_api(method, url, api_key, path, body=None):
        calls.append((method, path, body))
        if method == "GET":
            return 200, {"allowed_triggers": ["trig_old"]}
        if method == "PATCH":
            return 200, {"ok": True}
        raise AssertionError(method)

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    changed = admin.ensure_agent_trigger_binding("https://api.example", "admin", "agt_1", "trig_new")

    assert changed is True
    assert calls == [
        ("GET", "/v1/agents/agt_1", None),
        ("PATCH", "/v1/agents/agt_1", {"allowed_triggers": ["trig_new"]}),
    ]


def test_ensure_agent_trigger_binding_keeps_current_allowed_trigger(monkeypatch):
    calls = []

    def fake_cloud_api(method, url, api_key, path, body=None):
        calls.append((method, path, body))
        return 200, {"allowed_triggers": ["trig_new"]}

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    changed = admin.ensure_agent_trigger_binding("https://api.example", "admin", "agt_1", "trig_new")

    assert changed is False
    assert calls == [("GET", "/v1/agents/agt_1", None)]


def test_ensure_agent_trigger_binding_fails_on_patch_error(monkeypatch):
    def fake_cloud_api(method, url, api_key, path, body=None):
        if method == "GET":
            return 200, {"allowed_triggers": ["trig_old"]}
        return 403, {"error": {"code": "forbidden"}}

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    with pytest.raises(SystemExit, match="Reconcile agent trigger binding failed"):
        admin.ensure_agent_trigger_binding("https://api.example", "admin", "agt_1", "trig_new")


def test_ensure_agent_holder_claimed_no_op_when_keys_match(monkeypatch):
    calls = []

    def fake_cloud_api(method, url, api_key, path, body=None):
        calls.append((method, path))
        return 200, {"public_key": "aa" * 32}

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    changed = admin.ensure_agent_holder_claimed(
        "https://api.example", "runtime", "admin", "agt_1", "aa" * 32)

    assert changed is False
    assert calls == [("GET", "/v1/agents/agt_1")]


def test_ensure_agent_holder_claimed_rotates_and_claims(monkeypatch):
    calls = []

    def fake_cloud_api(method, url, api_key, path, body=None):
        calls.append((method, path, body))
        if method == "GET":
            return 200, {"public_key": "old" * 16}
        if method == "POST" and path.endswith("/rotate"):
            return 200, {"registration_token": "reg_tok"}
        if method == "POST" and path == "/v1/agents/claim":
            assert body == {
                "agent_id": "agt_1",
                "public_key": "new" * 16,
                "registration_token": "reg_tok",
            }
            assert api_key == "runtime"
            return 200, {"ok": True}
        raise AssertionError((method, path))

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    changed = admin.ensure_agent_holder_claimed(
        "https://api.example", "runtime", "admin", "agt_1", "new" * 16)

    assert changed is True
    assert calls == [
        ("GET", "/v1/agents/agt_1", None),
        ("POST", "/v1/agents/agt_1/rotate", {}),
        ("POST", "/v1/agents/claim", {
            "agent_id": "agt_1",
            "public_key": "new" * 16,
            "registration_token": "reg_tok",
        }),
    ]


def test_ensure_agent_holder_claimed_claims_when_cloud_has_no_key(monkeypatch):
    calls = []

    def fake_cloud_api(method, url, api_key, path, body=None):
        calls.append(method)
        if method == "GET":
            return 200, {"public_key": ""}
        if method == "POST" and path.endswith("/rotate"):
            return 200, {"registration_token": "reg_tok"}
        return 200, {"ok": True}

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    changed = admin.ensure_agent_holder_claimed(
        "https://api.example", "runtime", "admin", "agt_1", "new" * 16)

    assert changed is True
    assert calls == ["GET", "POST", "POST"]


def test_ensure_agent_holder_claimed_fails_on_claim_forbidden(monkeypatch):
    def fake_cloud_api(method, url, api_key, path, body=None):
        if method == "GET":
            return 200, {"public_key": "old" * 16}
        if method == "POST" and path.endswith("/rotate"):
            return 200, {"registration_token": "reg_tok"}
        return 403, {"error": {"code": "forbidden"}}

    monkeypatch.setattr(admin.tc, "cloud_api", fake_cloud_api)

    with pytest.raises(SystemExit, match="Re-claim agent failed"):
        admin.ensure_agent_holder_claimed(
            "https://api.example", "runtime", "admin", "agt_1", "new" * 16)


def test_build_warrant_config_mcp_approval_gate():
    cfg = {
        "_sandbox_abs": "/sandbox",
        "enforce": {
            "WebFetch": {
                "domains": ["api.github.com"],
                "approval": {"threshold": 1},
            },
        },
        "mcp": {
            "enforce": {
                "read_file": "subpath:{sandbox}",
                "delete_deployment": {
                    "approval": {
                        "threshold": 1,
                        "exempt": {"target": "exact:staging"},
                    },
                },
            },
        },
        "default": "deny",
        "audit": [],
    }
    wc = admin.build_warrant_config(cfg, "apol_test")

    assert wc["per_action_constraints"]["mcp__tenuo-files__delete_deployment"] == {
        "__tenuo_request": {"_type": "wildcard"},
        "target": {"_type": "wildcard"},
    }
    assert wc["per_action_constraints"]["mcp__tenuo-files__read_file"] == {
        "__tenuo_request": {"_type": "wildcard"},
        "path": {"_type": "subpath", "_value": "/sandbox"},
    }
    gates = wc["approval_gates"]
    assert gates["_policy_id"] == "apol_test"
    assert gates["mcp__tenuo-files__delete_deployment"]["args"]["target"]["exempt"] == {
        "_type": "exact",
        "_value": "staging",
    }
    assert "web_fetch" in gates
    assert gates["web_fetch"]["args"]["host"]["exempt"]["_type"] == "regex"


def test_build_warrant_config_mcp_approval_without_policy_skips_gate():
    cfg = {
        "_sandbox_abs": "/sandbox",
        "enforce": {},
        "mcp": {
            "enforce": {
                "delete_deployment": {
                    "approval": {"threshold": 1, "exempt": {"target": "exact:staging"}},
                },
            },
        },
        "default": "deny",
        "audit": [],
    }
    wc = admin.build_warrant_config(cfg, None)

    assert "delete_deployment" not in wc["per_action_constraints"]
    assert "approval_gates" not in wc


def test_build_warrant_config_default_approve_gates_catchall():
    # default: approve -> the catch-all cap is GRANTED (so unlisted tools aren't
    # hard-denied) but carries an approval gate, so they pause for human sign-off.
    cfg = {"_sandbox_abs": "/sandbox", "enforce": {"Read": "subpath:{sandbox}"},
           "mcp": {}, "default": "approve", "audit": []}
    wc = admin.build_warrant_config(cfg, "apol_test")
    catchall = admin.tc.CATCHALL_AUDIT
    assert catchall in wc["per_action_constraints"]          # granted (not denied)
    assert catchall in wc["actions"]
    # Whole-tool gate (args: None) requires approval for every unlisted call. The cap
    # wildcards `tool` only so the approval's request_hash binds per tool name.
    assert wc["per_action_constraints"][catchall] == {
        "__tenuo_request": {"_type": "wildcard"},"tool": {"_type": "wildcard"}}
    assert wc["approval_gates"][catchall] == {"args": None}
    assert wc["approval_gates"]["_policy_id"] == "apol_test"


def test_build_warrant_config_default_approve_without_policy_falls_back_to_deny():
    # No Cloud approval policy -> can't gate -> catch-all stays ungranted (deny).
    cfg = {"_sandbox_abs": "/sandbox", "enforce": {"Read": "subpath:{sandbox}"},
           "mcp": {}, "default": "approve", "audit": []}
    wc = admin.build_warrant_config(cfg, None)
    assert admin.tc.CATCHALL_AUDIT not in wc["per_action_constraints"]
    assert "approval_gates" not in wc


def test_build_warrant_config_native_tool_approval_gate():
    # enforce.<native>.approval -> wildcard the arg + gate it on the same arg, with
    # the user's exempt (safe values skip approval).
    cfg = {"_sandbox_abs": "/sandbox",
           "enforce": {"Bash": {"approval": {"threshold": 1, "exempt": "shlex:ls,pwd"}}},
           "mcp": {}, "default": "deny", "audit": []}
    wc = admin.build_warrant_config(cfg, "apol_test")
    assert wc["per_action_constraints"]["run_command"] == {
        "__tenuo_request": {"_type": "wildcard"},"command": {"_type": "wildcard"}}
    assert wc["approval_gates"]["run_command"]["args"]["command"]["exempt"] == {
        "_type": "shlex", "_value": ["ls", "pwd"]}
    assert wc["approval_gates"]["_policy_id"] == "apol_test"


def test_build_warrant_config_native_approval_no_exempt_uses_whole_tool_gate():
    # No exempt -> whole-tool gate (args: None) = tenuo-core's first-class "every
    # invocation requires approval", rather than a never-matching exempt sentinel.
    cfg = {"_sandbox_abs": "/sandbox",
           "enforce": {"Bash": {"approval": {"threshold": 1}}},
           "mcp": {}, "default": "deny", "audit": []}
    wc = admin.build_warrant_config(cfg, "apol_test")
    assert wc["per_action_constraints"]["run_command"] == {
        "__tenuo_request": {"_type": "wildcard"},"command": {"_type": "wildcard"}}
    assert wc["approval_gates"]["run_command"] == {"args": None}


def test_build_warrant_config_native_approval_without_policy_denies():
    cfg = {"_sandbox_abs": "/sandbox",
           "enforce": {"Bash": {"approval": {"threshold": 1}}},
           "mcp": {}, "default": "deny", "audit": []}
    wc = admin.build_warrant_config(cfg, None)
    assert "run_command" not in wc["per_action_constraints"]
    assert "approval_gates" not in wc
