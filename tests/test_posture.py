"""Posture model: mode (enforce/dry-run), default (deny/approve), allow-list.

Covers the redesigned vocabulary and its deprecated aliases (mode: audit,
default: audit|allow, audit:/audit_extra:/audit_bundled:). Pure logic + a couple
of load_config round-trips with a temp policy file; no Docker/authorizer/network.
See writing/hitl-mcp-gateway-plan.md and the posture redesign.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import tenuo_claude_code
from tenuo_claude_code import cli

_BUNDLED_HARNESS = Path(tenuo_claude_code.__file__).parent / "data" / "harness_tools.yaml"


# --- mode: enforce / dry-run (+ audit alias) --------------------------------

@pytest.mark.parametrize("value,dry_run", [
    (None, False), ("enforce", False),
    ("dry-run", True), ("dry_run", True), ("dryrun", True),
    ("audit", True),            # deprecated alias
    ("AUDIT", True),
])
def test_is_dry_run_mode(cli_mod, make_cfg, value, dry_run):
    cfg = make_cfg(mode=value) if value is not None else make_cfg()
    assert cli_mod.is_dry_run_mode(cfg) is dry_run


# --- default: approve pulls the catch-all into the approval set -------------

def test_approval_entries_includes_catchall_on_approve(cli_mod, make_cfg):
    assert not cli_mod.approval_entries(make_cfg(default="deny"))
    entries = cli_mod.approval_entries(make_cfg(default="approve"))
    caps = [c for c, _ in entries]
    assert cli_mod.CATCHALL_AUDIT in caps
    assert cli_mod.has_approval_gates(make_cfg(default="approve"))


# --- advisories: deprecations + local approve degradation -------------------

def test_posture_advisories_passes_through_deprecations(cli_mod, make_cfg):
    cfg = make_cfg()
    cfg["_deprecations"] = ["`mode: audit` is deprecated — rename to `mode: dry-run`"]
    assert "mode: audit" in " ".join(cli_mod.posture_advisories(cfg))


def test_posture_advisories_flags_local_approve(cli_mod, make_cfg, bound):
    # No Cloud creds (bound points cloud.env at a nonexistent temp path) -> approve
    # can't be honored -> advisory.
    notes = cli_mod.posture_advisories(make_cfg(default="approve"))
    assert any("requires Tenuo Cloud" in n for n in notes)


# --- _normalize_posture_keys: canonicalize + record deprecations ------------

def test_normalize_rejects_unknown_mode(cli_mod):
    with pytest.raises(SystemExit):
        cli_mod._normalize_posture_keys({"mode": "bogus"})


def test_normalize_rejects_unknown_default(cli_mod):
    with pytest.raises(SystemExit):
        cli_mod._normalize_posture_keys({"default": "bogus"})


@pytest.mark.parametrize("legacy", ["audit", "allow"])
def test_normalize_collapses_legacy_default_to_deny(cli_mod, legacy):
    cfg = {"default": legacy}
    deps = cli_mod._normalize_posture_keys(cfg)
    assert cfg["default"] == "deny"
    assert any("no longer supported" in d for d in deps)


def test_normalize_flags_deprecated_mode_audit(cli_mod):
    deps = cli_mod._normalize_posture_keys({"mode": "audit"})
    assert any("mode: audit" in d for d in deps)


def test_normalize_clean_policy_has_no_deprecations(cli_mod):
    assert cli_mod._normalize_posture_keys({"mode": "enforce", "default": "approve"}) == []


# --- ttl_seconds: configurable session warrant lifetime ---------------------

def test_session_ttl_defaults_to_3600(cli_mod, make_cfg):
    assert cli_mod.session_ttl_seconds(make_cfg()) == cli_mod.DEFAULT_SESSION_TTL_SECONDS == 3600


def test_session_ttl_uses_configured_value(cli_mod, make_cfg):
    assert cli_mod.session_ttl_seconds(make_cfg(ttl_seconds=900)) == 900


@pytest.mark.parametrize("bad", [0, -1, -3600, 3.5, "3600", True, False, None])
def test_validate_ttl_seconds_rejects_invalid(cli_mod, bad):
    # 0/negatives (non-positive), 3.5 (non-int), "3600" (str), True/False (bool is
    # not a duration), None (missing) all fail loud — never silently coerced.
    with pytest.raises(SystemExit, match="ttl_seconds"):
        cli_mod.validate_ttl_seconds(bad)


def test_validate_ttl_seconds_accepts_positive_int(cli_mod):
    assert cli_mod.validate_ttl_seconds(900) == 900


def test_load_config_rejects_invalid_ttl(cli_mod, tmp_path, monkeypatch):
    _write_policy(monkeypatch, tmp_path, "name: t\nttl_seconds: 0\n")
    with pytest.raises(SystemExit, match="ttl_seconds"):
        cli_mod.load_config()


def test_load_config_accepts_custom_ttl(cli_mod, tmp_path, monkeypatch):
    _write_policy(monkeypatch, tmp_path, "name: t\nttl_seconds: 1800\n")
    cfg = cli_mod.load_config()
    assert cli_mod.session_ttl_seconds(cfg) == 1800


def test_mint_local_warrant_default_ttl(cli_mod, make_cfg):
    """Absent `ttl_seconds` -> the minted session warrant carries the 1h default."""
    from tenuo import SigningKey

    cfg = make_cfg(enforce={"Read": "subpath:{sandbox}"})
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    w = cli_mod.mint_local_warrant(cfg, issuer, holder)
    assert w.ttl_seconds() == 3600


def test_mint_local_warrant_custom_ttl(cli_mod, make_cfg):
    """A configured `ttl_seconds` flows through to `.ttl(...)` on the minted warrant."""
    from tenuo import SigningKey

    cfg = make_cfg(enforce={"Read": "subpath:{sandbox}"}, ttl_seconds=900)
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    w = cli_mod.mint_local_warrant(cfg, issuer, holder)
    assert w.ttl_seconds() == 900


# --- load_config: allow / allow_bundled + legacy audit* aliases -------------

def _write_policy(monkeypatch, tmp_path, body: str):
    cfg_file = tmp_path / "tenuo.yaml"
    cfg_file.write_text(body)
    monkeypatch.setattr(cli, "CONFIG_FILE", cfg_file, raising=False)
    monkeypatch.setattr(cli, "DEMO_DIR", tmp_path, raising=False)
    monkeypatch.setattr(cli, "CLOUD_PROFILE", tmp_path / "nope-cloud.yaml", raising=False)
    monkeypatch.setattr(cli, "ADVANCED_PROFILE", tmp_path / "nope-adv.yaml", raising=False)
    monkeypatch.setattr(cli, "HARNESS_TOOLS_FILE", _BUNDLED_HARNESS, raising=False)


def test_load_config_allow_list_merges_with_bundled(cli_mod, tmp_path, monkeypatch):
    _write_policy(monkeypatch, tmp_path, "name: t\nallow:\n  - CustomReadOnly\n")
    cfg = cli_mod.load_config()
    assert "CustomReadOnly" in cfg["audit"]      # user allow entry present
    assert "TodoWrite" in cfg["audit"]           # bundled inert tool merged
    assert cfg["_deprecations"] == []


def test_load_config_allow_bundled_false_drops_bundled(cli_mod, tmp_path, monkeypatch):
    _write_policy(monkeypatch, tmp_path, "name: t\nallow_bundled: false\nallow:\n  - OnlyThis\n")
    cfg = cli_mod.load_config()
    assert cfg["audit"] == ["OnlyThis"]


def test_load_config_deny_overrides_bundled_allow(cli_mod, tmp_path, monkeypatch):
    _write_policy(monkeypatch, tmp_path, "name: t\ndeny:\n  - WebSearch\n")
    cfg = cli_mod.load_config()
    assert "WebSearch" not in cfg["audit"]
    assert "TodoWrite" in cfg["audit"]


@pytest.mark.parametrize("body", [
    "name: t\nallow:\n  - WebSearch\ndeny:\n  - WebSearch\n",
    "name: t\nenforce:\n  Read: 'subpath:.'\ndeny:\n  - Read\n",
    "name: t\ndeny: WebSearch\n",
    "name: t\nmcp:\n  enforce:\n    delete_repository: 'exact:x'\ndeny:\n  - delete_repository\n",
])
def test_load_config_deny_conflicts_fail_loud(cli_mod, tmp_path, monkeypatch, body):
    _write_policy(monkeypatch, tmp_path, body)
    with pytest.raises(SystemExit, match="deny"):
        cli_mod.load_config()


def test_load_config_legacy_audit_keys_alias_with_deprecation(cli_mod, tmp_path, monkeypatch):
    _write_policy(monkeypatch, tmp_path,
                  "name: t\naudit:\n  - LegacyTool\naudit_extra:\n  - ExtraTool\naudit_bundled: false\n")
    cfg = cli_mod.load_config()
    assert set(cfg["audit"]) == {"LegacyTool", "ExtraTool"}   # bundled disabled
    joined = " ".join(cfg["_deprecations"])
    assert "`audit:`" in joined and "audit_extra" in joined and "audit_bundled" in joined


def test_load_config_legacy_default_audit_becomes_deny(cli_mod, tmp_path, monkeypatch):
    _write_policy(monkeypatch, tmp_path, "name: t\ndefault: audit\n")
    cfg = cli_mod.load_config()
    assert cfg["default"] == "deny"
    assert cli_mod.default_mode(cfg) == "deny"
    assert any("no longer supported" in d for d in cfg["_deprecations"])


# --- default: approve defers fail-closed enforcement to core ----------------
# The fail-closed guarantee is the warrant's whole-tool approval gate — tenuo-core
# requires a signed human approval for every catch-all invocation, and the cap is
# granted only alongside that gate (locally it's never granted, so approve falls
# back to deny). The plugin no longer re-derives that decision at runtime. The gate
# wire shape is asserted in test_admin (…default_approve_gates_catchall) and the
# enforcement in tenuo-core; here we only assert the routing the plugin still owns.

def test_approve_routes_unlisted_to_gated_catchall(cli_mod, make_cfg):
    cap, route, *_ = cli_mod.resolve_tool(make_cfg(default="approve"), "SomeUnlistedTool", {})
    assert cap == cli_mod.CATCHALL_AUDIT and route == "/gate"


def test_deny_routes_unlisted_to_ungranted_catchall(cli_mod, make_cfg):
    cap, *_ = cli_mod.resolve_tool(make_cfg(default="deny"), "SomeUnlistedTool", {})
    assert cap == cli_mod.CATCHALL_DENY


# --- per-tool human approval on native enforce tools (Cloud HiTL) -----------

def test_governed_map_parses_native_approval(cli_mod, make_cfg):
    cfg = make_cfg(enforce={"Bash": {"approval": {"threshold": 1, "exempt": "shlex:ls,pwd"}}})
    g = cli_mod.governed_map(cfg)["Bash"]
    assert g["cap"] == "run_command" and g["arg"] == "command"
    assert g["approval"] == {"threshold": 1}     # exempt popped off the approval block
    assert g["exempt"] == "shlex:ls,pwd"


def test_governed_map_rejects_structured_without_approval(cli_mod, make_cfg):
    # A dict on a non-WebFetch tool must carry an approval block — nothing else.
    with pytest.raises(SystemExit):
        cli_mod.governed_map(make_cfg(enforce={"Bash": {"constraint": "shlex:ls"}}))


def test_governed_map_rejects_nonstring_exempt(cli_mod, make_cfg):
    with pytest.raises(SystemExit):
        cli_mod.governed_map(make_cfg(enforce={"Bash": {"approval": {"exempt": {"x": "y"}}}}))


def test_approval_entries_includes_native_tool(cli_mod, make_cfg):
    cfg = make_cfg(enforce={"Bash": {"approval": {"threshold": 1}}})
    assert "run_command" in [c for c, _ in cli_mod.approval_entries(cfg)]
    assert cli_mod.has_approval_gates(cfg)


def test_native_approval_relaxes_to_wildcard_under_cloud(cli_mod, make_cfg, monkeypatch):
    tenuo_core = pytest.importorskip("tenuo_core")
    pytest.importorskip("tenuo")
    cfg = make_cfg(enforce={"Bash": {"approval": {"threshold": 1}}})
    monkeypatch.setattr(cli_mod, "use_cloud_trigger", lambda c: True)   # Cloud issuing
    caps = cli_mod.enforced_capabilities(cfg)
    assert isinstance(caps["run_command"]["command"], tenuo_core.Wildcard)


def test_native_approval_not_granted_without_cloud(cli_mod, make_cfg, monkeypatch):
    pytest.importorskip("tenuo_core")
    pytest.importorskip("tenuo")
    cfg = make_cfg(enforce={"Bash": {"approval": {"threshold": 1}}})
    monkeypatch.setattr(cli_mod, "use_cloud_trigger", lambda c: False)  # no Cloud
    assert "run_command" not in cli_mod.enforced_capabilities(cfg)   # Cloud-only → denied locally


def test_native_approval_not_relaxed_when_only_stale_trigger_id(cli_mod, make_cfg, monkeypatch):
    # A stale trigger_id with no creds must NOT relax the constraint: the warrant
    # would be minted locally (no approval gate), so a wildcard grant would be
    # fail-open. use_cloud_trigger requires creds, so the cap stays denied.
    pytest.importorskip("tenuo_core")
    pytest.importorskip("tenuo")
    cfg = make_cfg(enforce={"Bash": {"approval": {"threshold": 1}}})
    monkeypatch.setattr(cli_mod, "trigger_id", lambda c: "trig_stale")   # lingering state
    monkeypatch.setattr(cli_mod, "cloud_creds", lambda c: {"url": None, "api_key": None})
    assert cli_mod.use_cloud_trigger(cfg) is False
    assert "run_command" not in cli_mod.enforced_capabilities(cfg)


def test_posture_advisory_flags_native_approval_without_cloud(cli_mod, make_cfg, bound):
    cfg = make_cfg(enforce={"Bash": {"approval": {"threshold": 1}}})
    assert any("requires Tenuo Cloud" in n for n in cli_mod.posture_advisories(cfg))
