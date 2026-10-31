"""resolve_tool / mcp_tool_name / the small policy helpers — pure logic."""
from __future__ import annotations

import json
import os

import pytest


# --- mcp_tool_name ----------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("mcp__tenuo-files__read_file", "read_file"),
    ("mcp__server__multi_word_tool", "multi_word_tool"),  # underscores preserved
    ("Read", None),
    ("mcp__server__", None),       # empty tool segment
    ("mcp__server", None),         # only two segments
    ("", None),
])
def test_mcp_tool_name(cli_mod, name, expected):
    assert cli_mod.mcp_tool_name(name) == expected


# --- default_mode / catchall_cap -------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (None, "deny"), ("deny", "deny"), ("approve", "approve"), ("APPROVE", "approve"),
    ("allow", "deny"), ("audit", "deny"), ("nonsense", "deny"),
])
def test_default_mode(cli_mod, make_cfg, value, expected):
    cfg = make_cfg(default=value)
    assert cli_mod.default_mode(cfg) == expected

def test_catchall_cap(cli_mod, make_cfg):
    assert cli_mod.catchall_cap(make_cfg(default="deny")) == "unlisted"
    assert cli_mod.catchall_cap(make_cfg(default="approve")) == "audit"
    assert cli_mod.catchall_cap(make_cfg(default="audit")) == "unlisted"
    assert cli_mod.catchall_cap(make_cfg(default="allow")) == "unlisted"


# --- posture: mode dry-run / audit alias / warnings ------------------------

@pytest.mark.parametrize("value,observe", [
    ("enforce", False),
    ("dry-run", True),      # canonical observe-only
    ("dry_run", True),      # forgiving spelling
    ("audit", True),        # deprecated alias still works
    ("AUDIT", True),        # case-insensitive
    (None, False),          # default is enforce
    ("allow", False),       # belongs on default:, not mode: -> fail-closed to enforce
    ("nonsense", False),    # unknown -> enforce
])
def test_policy_mode_and_is_audit_mode(cli_mod, make_cfg, value, observe):
    cfg = make_cfg(mode=value)
    assert cli_mod.is_audit_mode(cfg) is observe
    assert cli_mod.policy_mode(cfg) == (cli_mod.MODE_DRY_RUN if observe else cli_mod.MODE_ENFORCE)


def test_posture_warnings_clean_for_canonical(cli_mod, make_cfg):
    assert cli_mod.posture_warnings(make_cfg(mode="enforce", default="deny")) == []
    assert cli_mod.posture_warnings(make_cfg(mode="dry-run", default="deny")) == []


def test_posture_warnings_flags_deprecated_audit_mode(cli_mod, make_cfg):
    warns = cli_mod.posture_warnings(make_cfg(mode="audit"))
    assert any("deprecated" in w and "dry-run" in w for w in warns)


# --- managed Cloud mode ----------------------------------------------------

def test_managed_mode_from_resolved_flag(cli_mod, make_cfg):
    assert cli_mod.managed_mode(make_cfg(_managed=True)) is True
    assert cli_mod.managed_mode(make_cfg(_managed=False)) is False


def test_managed_mode_from_cloud_policy_without_disk(cli_mod):
    """cloud.managed short-circuits before reading cloud_state.json from disk."""
    assert cli_mod.managed_mode({"cloud": {"managed": True}}) is True


def test_managed_pins_enforce_posture(cli_mod, make_cfg):
    # dry-run is observe-only on an unmanaged endpoint...
    assert cli_mod.is_audit_mode(make_cfg(mode="dry-run", _managed=False)) is True
    # ...but managed Cloud mode pins it to enforce (never observe-only).
    assert cli_mod.is_audit_mode(make_cfg(mode="dry-run", _managed=True)) is False


def test_posture_warning_notes_managed_pin(cli_mod, make_cfg):
    warns = cli_mod.posture_warnings(make_cfg(mode="dry-run", _managed=True))
    assert any("pinned to enforce" in w and "managed" in w for w in warns)


def test_managed_enforce_pinned_reads_env(cli_mod, monkeypatch):
    monkeypatch.delenv("TENUO_MANAGED_ENFORCE", raising=False)
    assert cli_mod._managed_enforce_pinned() is False
    monkeypatch.setenv("TENUO_MANAGED_ENFORCE", "1")
    assert cli_mod._managed_enforce_pinned() is True
    monkeypatch.setenv("TENUO_MANAGED_ENFORCE", "0")
    assert cli_mod._managed_enforce_pinned() is False


def test_pinned_managed_hook_overrides_local_observe(cli_mod, make_cfg, monkeypatch):
    """P1 regression: a developer who edits local state to drop the managed flag
    AND set mode: dry-run must NOT be able to make the MDM-pinned hook observe-only."""
    cfg = make_cfg(mode="dry-run", _managed=False)
    assert cli_mod.is_audit_mode(cfg) is True  # editable view: observe-only
    # The pinned `_managed-hook` sets this env; it can't be forged away locally.
    monkeypatch.setenv("TENUO_MANAGED_ENFORCE", "1")
    assert cli_mod.managed_mode(cfg) is True
    assert cli_mod.is_audit_mode(cfg) is False  # enforce, regardless of local edits


def test_local_widened_tools_flags_tools_absent_from_warrant(cli_mod, make_cfg):
    cfg = make_cfg(audit=["WebSearch"])
    cap = cli_mod.audit_map(cfg)["WebSearch"]
    # Warrant grants nothing -> the locally-governed tool is a widening.
    assert cli_mod.local_widened_tools(cfg, {}) == [cap]
    # Warrant grants it -> local merely narrows/matches, no widening.
    assert cli_mod.local_widened_tools(cfg, {cap: {}}) == []
    # No readable warrant -> we can't tell, so we make no widening claim.
    assert cli_mod.local_widened_tools(cfg, None) == []


def test_local_widened_tools_ignores_synthetic_catchall(cli_mod, make_cfg):
    # default: approve adds the synthetic 'audit' catch-all cap; it's a routing
    # artifact for the approval gate, so it must never count as widening.
    cfg = make_cfg(default="approve")
    assert cli_mod.CATCHALL_AUDIT not in cli_mod.local_widened_tools(cfg, {})


def test_assert_managed_runtime_fails_closed_without_trigger(cli_mod, make_cfg):
    """The core security invariant: managed mode must NOT fall back to a local
    warrant when no Cloud trigger is available."""
    with pytest.raises(SystemExit):
        cli_mod._assert_managed_runtime(make_cfg(_managed=True), use_trigger=False)
    # Managed + a Cloud trigger present -> allowed.
    cli_mod._assert_managed_runtime(make_cfg(_managed=True), use_trigger=True)
    # Unmanaged -> local/Cloud fallback is fine, never raises.
    cli_mod._assert_managed_runtime(make_cfg(_managed=False), use_trigger=False)


# --- audit_map --------------------------------------------------------------

def test_audit_map_known_and_unknown(cli_mod, make_cfg):
    cfg = make_cfg(audit=["WebSearch", "CustomThing"])
    m = cli_mod.audit_map(cfg)
    assert m["WebSearch"] == "web_search"      # from TOOL_DEFAULTS
    assert m["CustomThing"] == "customthing"   # slug() fallback


# --- subagent_roles / webfetch_approval ------------------------------------

def test_subagent_roles(cli_mod, make_cfg):
    assert cli_mod.subagent_roles(make_cfg()) == {}
    roles = {"researcher": {"tools": ["Read"]}}
    assert cli_mod.subagent_roles(make_cfg(subagents=roles)) == roles


def test_webfetch_approval(cli_mod, make_cfg):
    assert cli_mod.webfetch_approval(make_cfg()) is None
    # plain string policy -> not a dict -> no approval block
    assert cli_mod.webfetch_approval(make_cfg(enforce={"WebFetch": "x"})) is None
    # structured, no approval
    assert cli_mod.webfetch_approval(
        make_cfg(enforce={"WebFetch": {"domains": ["a.com"]}})) is None
    # structured, with approval
    appr = {"threshold": 2}
    got = cli_mod.webfetch_approval(
        make_cfg(enforce={"WebFetch": {"domains": ["a.com"], "approval": appr}}))
    assert got == appr


# --- governed_map -----------------------------------------------------------

def test_validate_webfetch_policy_rejects_approval_with_cidrs(cli_mod):
    # Approval wildcards the host + drops block_private, so a cidrs allowlist
    # would silently widen to all private ranges -> refuse the combination.
    cfg = {"enforce": {"WebFetch": {
        "cidrs": ["10.0.0.0/8"], "approval": {"threshold": 1}}}}
    with pytest.raises(SystemExit, match="cannot be combined with `cidrs`"):
        cli_mod.validate_webfetch_policy(cfg)


def test_validate_webfetch_policy_allows_approval_with_domains(cli_mod):
    # domains + approval is the supported shape and must not raise.
    cfg = {"enforce": {"WebFetch": {
        "domains": ["api.github.com"], "approval": {"threshold": 1}}}}
    cli_mod.validate_webfetch_policy(cfg)  # no raise


def test_governed_map_unknown_tool_raises(cli_mod, make_cfg):
    with pytest.raises(SystemExit):
        cli_mod.governed_map(make_cfg(enforce={"Frobnicate": "subpath:/x"}))


def test_governed_map_structured_only_for_webfetch(cli_mod, make_cfg):
    with pytest.raises(SystemExit):
        cli_mod.governed_map(make_cfg(enforce={"Read": {"domains": ["a.com"]}}))


def test_governed_map_webfetch_structured(cli_mod, make_cfg):
    gov = cli_mod.governed_map(make_cfg(enforce={"WebFetch": {"domains": ["a.com"]}}))
    assert gov["WebFetch"]["cap"] == "web_fetch"
    assert "web" in gov["WebFetch"]


# --- resolve_tool -----------------------------------------------------------

def test_resolve_tool_enforced_subpath_realpaths(cli_mod, make_cfg, tmp_path):
    sb = str(tmp_path)
    cfg = make_cfg(enforce={"Read": "subpath:" + sb}, _sandbox_abs=sb)
    target = tmp_path / "notes.txt"
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "Read", {"file_path": str(target)})
    assert cap == "read_file"
    assert route == "/verify/read_file"
    assert governed is True
    assert sign_args["path"] == os.path.realpath(str(target))


def test_resolve_tool_bash_passthrough(cli_mod, make_cfg):
    cfg = make_cfg(enforce={"Bash": "shlex:ls,echo"})
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "Bash", {"command": "ls -la"})
    assert cap == "run_command"
    assert sign_args["command"] == "ls -la"
    assert governed is True


@pytest.mark.parametrize("tool,cap", [
    ("PowerShell", "run_powershell"),
    ("Monitor", "run_monitor"),
])
def test_resolve_tool_command_exec_tools(cli_mod, make_cfg, tool, cap):
    cfg = make_cfg(enforce={tool: "oneof:Get-ChildItem"})
    rcap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, tool, {"command": "Get-ChildItem"})
    assert rcap == cap
    assert route == f"/verify/{cap}"
    assert sign_args == {"command": "Get-ChildItem"}
    assert governed is True


def test_command_exec_tools_get_independent_capabilities(cli_mod, make_cfg):
    """Bash/PowerShell/Monitor must NOT collapse to one capability: a shared cap
    would silently drop a second tool's constraint under the first-wins de-dup."""
    cfg = make_cfg(enforce={
        "Bash": "shlex:ls,echo",
        "PowerShell": "oneof:Get-ChildItem",
        "Monitor": "shlex:tail,cat",
    })
    caps = cli_mod.enforced_capabilities(cfg)
    assert {"run_command", "run_powershell", "run_monitor"} <= set(caps)
    # each carries its own command constraint, none dropped
    assert set(caps["run_command"]) == {"command"}
    assert set(caps["run_powershell"]) == {"command"}
    assert set(caps["run_monitor"]) == {"command"}
    assert type(caps["run_command"]["command"]).__name__ == "Shlex"
    assert type(caps["run_powershell"]["command"]).__name__ == "OneOf"


def test_resolve_tool_webfetch_extracts_host(cli_mod, make_cfg):
    cfg = make_cfg(enforce={"WebFetch": {"domains": ["api.github.com"]}})
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "WebFetch", {"url": "https://api.github.com/repos"})
    assert cap == "web_fetch"
    assert sign_args == {"url": "https://api.github.com/repos", "host": "api.github.com"}
    assert governed is True


def test_resolve_tool_audit_listed(cli_mod, make_cfg):
    cfg = make_cfg(audit=["WebSearch"])
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "WebSearch", {"query": "x"})
    assert cap == "web_search"
    assert governed is False
    assert sign_args == {}            # audit tools carry no constraint args
    assert body == {"query": "x"}


def test_resolve_tool_catchall_deny(cli_mod, make_cfg):
    cfg = make_cfg(default="deny")
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "NotebookEdit", {"notebook_path": "x.ipynb"})
    assert cap == "unlisted"          # ungranted -> signed DENY
    assert route == "/gate"
    assert governed is False


def test_resolve_tool_catchall_approve(cli_mod, make_cfg):
    # default: approve routes unlisted tools to the granted catch-all cap (gated in
    # the Cloud warrant -> human approval). default: deny routes to ungranted "unlisted".
    cap, *_ = cli_mod.resolve_tool(make_cfg(default="approve"), "SomethingNew", {})
    assert cap == "audit"
    cap, *_ = cli_mod.resolve_tool(make_cfg(default="deny"), "SomethingNew", {})
    assert cap == "unlisted"


def test_resolve_tool_mcp_bare_name(cli_mod, make_cfg, tmp_path):
    cfg = make_cfg(mcp={"enforce": {"read_file": "subpath:/sb"}})
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "read_file", {"path": str(tmp_path / "f")})
    assert cap == "read_file"
    assert route == "/verify/read_file"
    assert governed is True


def test_resolve_tool_mcp_prefixed_name(cli_mod, make_cfg, tmp_path):
    cfg = make_cfg(mcp={"enforce": {"read_file": "subpath:/sb"}})
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "mcp__tenuo-files__read_file", {"path": str(tmp_path / "f")})
    assert cap == "read_file"
    assert governed is True


def test_resolve_tool_mcp_unenforced_falls_to_catchall(cli_mod, make_cfg):
    # delete_deployment is intentionally NOT in mcp.enforce -> default-deny.
    cfg = make_cfg(mcp={"enforce": {"read_file": "subpath:/sb"}}, default="deny")
    cap, route, *_ , governed = cli_mod.resolve_tool(
        cfg, "mcp__tenuo-files__delete_deployment", {"target": "production"})
    assert cap == "unlisted"
    assert route == "/gate"
    assert governed is False


def test_load_config_never_auto_audits_command_exec_tools(cli_mod, monkeypatch, tmp_path):
    """The shipped harness bundle is auto-audited (allow+log). A command-exec tool
    slipping into it would grant an unconstrained shell, so load_config drops them."""
    cfg_file = tmp_path / "tenuo.yaml"
    cfg_file.write_text("name: t\nsandbox: ./sb\nallow:\n  - WebSearch\n")
    monkeypatch.setattr(cli_mod, "CONFIG_FILE", cfg_file, raising=False)
    monkeypatch.setattr(cli_mod, "CLOUD_PROFILE", tmp_path / "none1", raising=False)
    monkeypatch.setattr(cli_mod, "ADVANCED_PROFILE", tmp_path / "none2", raising=False)
    monkeypatch.setattr(cli_mod, "DEMO_DIR", tmp_path, raising=False)
    # simulate a future edit that adds a shell to the bundled audit list
    monkeypatch.setattr(cli_mod, "load_harness_tools",
                        lambda: ["WebSearch", "Bash", "Monitor", "PowerShell"])
    audit = cli_mod.load_config()["audit"]
    assert "WebSearch" in audit                       # harmless harness tool kept
    assert not (cli_mod.COMMAND_EXEC_TOOLS & set(audit))  # shells dropped


@pytest.mark.parametrize("spec,expected", [
    # approval-only: no arg constraints; approval + exempt split out
    ({"approval": {"threshold": 1, "exempt": {"target": "exact:staging"}}},
     {"constraints": {}, "approval": {"threshold": 1}, "exempt_args": {"target": "exact:staging"}}),
    # bare string and explicit `constraint:` both pin the default `path` arg
    ("subpath:/sb", {"constraints": {"path": "subpath:/sb"}}),
    ({"constraint": "subpath:/sb"}, {"constraints": {"path": "subpath:/sb"}}),
    # named single arg
    ({"arg": "sql", "constraint": "regex:^SELECT"}, {"constraints": {"sql": "regex:^SELECT"}}),
    # multi-arg
    ({"args": {"url": "urlpattern:https://x/*", "method": "oneof:GET,HEAD"}},
     {"constraints": {"url": "urlpattern:https://x/*", "method": "oneof:GET,HEAD"}}),
])
def test_parse_mcp_enforce_valid(cli_mod, spec, expected):
    parsed = cli_mod.parse_mcp_enforce_spec(spec)
    for key, val in expected.items():
        assert parsed[key] == val


@pytest.mark.parametrize("spec,match", [
    ({"arg": "sql"}, None),                                                   # arg w/o constraint
    ({"args": {"a": "exact:x"}, "arg": "b", "constraint": "exact:y"}, None),  # args+arg combo
    ({"path": "target", "constraint": "exact:production"}, "path:"),          # legacy path alias
    ({"constriant": "exact:x"}, "unknown key"),                               # typo / unknown key
    ({"args": {"": "exact:x"}}, "cannot be empty"),                           # empty arg name
    ({"arg": "  ", "constraint": "exact:x"}, "cannot be empty"),              # whitespace arg name
])
def test_parse_mcp_enforce_invalid(cli_mod, spec, match):
    with pytest.raises(SystemExit, match=match):
        cli_mod.parse_mcp_enforce_spec(spec)


def test_resolve_tool_mcp_named_arg(cli_mod, make_cfg):
    cfg = make_cfg(mcp={"enforce": {"run_query": {"arg": "sql", "constraint": "regex:^SELECT"}}})
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "run_query", {"sql": "SELECT 1", "other": "ignored"})
    assert cap == "run_query"
    assert route == "/verify/run_query"
    assert sign_args == {"sql": "SELECT 1"}     # only the constrained arg is signed
    assert governed is True


def test_resolve_tool_mcp_multi_arg(cli_mod, make_cfg):
    cfg = make_cfg(mcp={"enforce": {"http_call": {
        "args": {"url": "urlpattern:https://api.example.com/*", "method": "oneof:GET,HEAD"}}}})
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "http_call", {"url": "https://api.example.com/v1", "method": "GET"})
    assert cap == "http_call"
    assert sign_args == {"url": "https://api.example.com/v1", "method": "GET"}
    assert governed is True


def test_enforced_capabilities_mcp_named_and_multi_arg(cli_mod, make_cfg):
    cfg = make_cfg(mcp={"enforce": {
        "run_query": {"arg": "sql", "constraint": "regex:^SELECT"},
        "http_call": {"args": {"url": "urlpattern:https://x/*", "method": "oneof:GET"}},
    }})
    caps = cli_mod.enforced_capabilities(cfg)
    assert set(caps["run_query"]) == {"sql"}
    assert set(caps["http_call"]) == {"url", "method"}


def test_approval_entries_native_and_mcp(cli_mod, make_cfg):
    cfg = make_cfg(
        enforce={"WebFetch": {"domains": ["a.com"], "approval": {"threshold": 1}}},
        mcp={"enforce": {"delete_deployment": {"approval": {"threshold": 1}}}},
    )
    caps = {cap for cap, _ in cli_mod.approval_entries(cfg)}
    assert caps == {"web_fetch", "delete_deployment"}


def test_resolve_tool_mcp_delete_deployment_target(cli_mod, make_cfg):
    cfg = make_cfg(mcp={"enforce": {"delete_deployment": {
        "approval": {"threshold": 1, "exempt": {"target": "exact:staging"}},
    }}})
    cap, route, sign_args, body, governed = cli_mod.resolve_tool(
        cfg, "delete_deployment", {"target": "production"})
    assert cap == "delete_deployment"
    assert route == "/verify/delete_deployment"
    assert sign_args == {"target": "production"}
    assert governed is True


def test_authorizer_running_false_without_docker(cli_mod, monkeypatch, tmp_path):
    """Docker-less host (macOS/WSL on the native backend): with no native state
    recorded, report not-running rather than hard-failing on a missing `docker`."""
    monkeypatch.setattr(cli_mod, "authorizer_mount_dir", lambda: tmp_path)
    monkeypatch.setattr(cli_mod.art, "read_runtime_backend", lambda _m: None)
    monkeypatch.setattr(cli_mod.art, "native_pid_path", lambda _m: tmp_path / "absent.pid")
    monkeypatch.setattr(cli_mod.shutil, "which", lambda _name: None)

    def _no_docker(*_a):
        raise AssertionError("docker must not be invoked when Docker is absent")
    monkeypatch.setattr(cli_mod, "docker", _no_docker)

    assert cli_mod.authorizer_running({"name": "x"}) is False


def test_status_json_uses_separate_local_health_listener(cli_mod, monkeypatch):
    seen = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"version": "0.3.5+authz.3"}).encode()

    monkeypatch.setattr(cli_mod, "authz_endpoint", lambda: ("tcp", cli_mod.AUTHZ_URL))
    monkeypatch.setattr(
        cli_mod.urllib.request,
        "urlopen",
        lambda url, timeout: seen.append((url, timeout)) or Response(),
    )

    assert cli_mod._status_json() == {"version": "0.3.5+authz.3"}
    assert seen == [(cli_mod.HEALTH_URL + "/status", 3)]
