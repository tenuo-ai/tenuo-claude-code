"""Managed-mode (MDM) template generation.

These artifacts are the enforcing half of managed Cloud mode (threat T6): they
must pin the real, resolvable hook command and the cloud-root-only trust anchor.
A wrong template sells false assurance, so we assert the security-critical shape.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

PINNED_BIN = "/opt/tenuo/venv/bin/python"


@pytest.fixture
def fleet(monkeypatch, bound):
    """A bound temp project with a uniform fleet-wide launcher path pinned, so the
    hook command resolves without depending on the test machine's PATH/venv."""
    monkeypatch.setenv("TENUO_CLAUDE_BIN", "/untrusted/project/bin/tenuo-claude")
    monkeypatch.setattr("tenuo_claude_code.managed_runtime.validate_managed_python", lambda p: PINNED_BIN)
    return bound


def test_managed_settings_lock_down_keys(cli_mod, make_cfg, fleet):
    s = cli_mod.managed_claude_settings(make_cfg())
    assert s["allowManagedHooksOnly"] is True
    assert s["allowManagedPermissionRulesOnly"] is True
    # Documented as the string "disable", not a boolean — get this wrong and
    # --dangerously-skip-permissions is NOT blocked.
    assert s["permissions"]["disableBypassPermissionsMode"] == "disable"
    # ENTERPRISE.md baseline also forbids auto-accept mode.
    assert s["permissions"]["disableAutoMode"] == "disable"


def test_managed_settings_pins_resolvable_hook(cli_mod, make_cfg, fleet):
    s = cli_mod.managed_claude_settings(make_cfg())
    pre = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    post = s["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert PINNED_BIN in pre and "_managed-hook" in pre
    assert PINNED_BIN in post and "_post" in post


def test_managed_settings_pins_managed_hook_entrypoint(cli_mod, make_cfg, fleet):
    """PreToolUse must use `_managed-hook` (enforcement anchored in the artifact),
    not plain `_hook` (which honors editable local posture)."""
    s = cli_mod.managed_claude_settings(make_cfg())
    pre = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "_managed-hook" in pre
    # PostToolUse is receipts-only and stays the plain _post entrypoint.
    post = s["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert "_post" in post and "_managed-hook" not in post


def test_managed_settings_mcp_lockdown_only_when_proxy_configured(cli_mod, make_cfg, fleet):
    bare = cli_mod.managed_claude_settings(make_cfg())
    assert "allowManagedMcpServersOnly" not in bare

    withmcp = cli_mod.managed_claude_settings(make_cfg(mcp={"downstream": "files-server"}))
    assert withmcp["allowManagedMcpServersOnly"] is True
    assert withmcp["allowedMcpServers"] == [{"serverName": cli_mod.MCP_SERVER_NAME}]
    assert cli_mod.managed_mcp_config(make_cfg(mcp={"downstream": "files-server"})) is not None


def test_managed_mcp_config_pins_managed_proxy_entrypoint(cli_mod, make_cfg, fleet):
    """The managed MCP server must run `_managed-mcp-proxy`, not the plain proxy,
    so it can't be downgraded to observe-only via local state (P1)."""
    cfg = make_cfg(mcp={"downstream": "files-server"})
    server = cli_mod.managed_mcp_config(cfg)["mcpServers"][cli_mod.MCP_SERVER_NAME]
    invocation = " ".join([server["command"], *server["args"]])
    assert "_managed-mcp-proxy" in invocation
    # And no managed proxy entry when the policy declares no downstream server.
    assert cli_mod.managed_mcp_config(make_cfg()) is None


def test_managed_hook_ignores_editable_authorizer_url(cli_mod, monkeypatch, tmp_path):
    """The pinned managed hook must not honor the editable state.json override."""
    state_json = tmp_path / "state.json"
    state_json.write_text(json.dumps({"authorizer_url": "http://attacker.example:1234"}))
    monkeypatch.setattr(cli_mod, "STATE_JSON", state_json, raising=False)
    monkeypatch.setattr(cli_mod, "AUTHZ_URL", "http://127.0.0.1:9090", raising=False)

    monkeypatch.delenv("TENUO_MANAGED_ENFORCE", raising=False)
    assert cli_mod.resolve_authz_url() == "http://attacker.example:1234"  # cooperative path honors it
    monkeypatch.setenv("TENUO_MANAGED_ENFORCE", "1")
    assert cli_mod.resolve_authz_url() == "http://127.0.0.1:9090"  # managed ignores it


def test_authz_docker_argv_is_cloud_root_only(cli_mod, make_cfg, fleet):
    argv = cli_mod._authz_docker_argv(make_cfg())
    trusted = [a for a in argv if a.startswith("TENUO_TRUSTED_KEYS=")]
    assert len(trusted) == 1
    # cloud root ONLY: no second (local issuer) key appended via comma.
    assert "," not in trusted[0]
    # never the local issuer public key file content.
    assert all("issuer" not in a.lower() for a in argv)
    assert cli_mod.DEFAULT_AUTHZ_IMAGE in argv  # pinned version floor, not :latest


def test_authz_serves_unix_socket_not_tcp(cli_mod, make_cfg, fleet):
    """The managed authorizer must serve on the root-owned Unix socket the hook
    authenticates by ownership — NOT loopback TCP, which a process can race."""
    argv = cli_mod._authz_docker_argv(make_cfg())
    assert "--socket" in argv
    assert argv[argv.index("--socket") + 1] == cli_mod.DEFAULT_AUTHZ_SOCKET
    # No TCP surface: no published port, no --port/--bind.
    assert "-p" not in argv and "--port" not in argv and "--bind" not in argv
    # The socket dir is bind-mounted so the socket appears (root-owned) on the host.
    sock_dir = os.path.dirname(cli_mod.DEFAULT_AUTHZ_SOCKET)
    assert f"{sock_dir}:{sock_dir}" in argv


def test_authz_container_runs_as_root(cli_mod, make_cfg, fleet):
    """The image's default user is uid 1000, which can't create the socket in the
    root-owned RuntimeDirectory (EACCES). The unit must force root (`-u 0:0`) so the
    daemon can bind and the socket is root-owned on the host."""
    argv = cli_mod._authz_docker_argv(make_cfg())
    assert "-u" in argv and argv[argv.index("-u") + 1] == "0:0"


def test_authz_socket_is_connectable_by_unprivileged_hook(cli_mod, make_cfg, fleet):
    """The root-owned socket defaults to 0660, which the unprivileged hook can't
    connect to. The unit must pass `--socket-mode 0666` so the hook can reach it
    (ownership, not connect perms, is the trust boundary)."""
    argv = cli_mod._authz_docker_argv(make_cfg())
    assert "--socket-mode" in argv and argv[argv.index("--socket-mode") + 1] == "0666"
    # macOS native daemon (also root) needs the same so the hook can connect.
    assert "--socket-mode 0666" in cli_mod.launchd_plist_template(make_cfg())


def test_authz_socket_group_generates_hardened_connect_mode(cli_mod, make_cfg, fleet):
    """Enterprises can avoid world-connectable sockets without hand-editing units:
    socket_group keeps root ownership but limits connect permission to that group."""
    cfg = make_cfg(authorizer={"socket_group": "tenuo"})
    argv = cli_mod._authz_docker_argv(cfg)
    assert "--socket-group" in argv and argv[argv.index("--socket-group") + 1] == "tenuo"
    assert "--socket-mode" in argv and argv[argv.index("--socket-mode") + 1] == "0660"
    unit = cli_mod.systemd_unit_template(cfg)
    assert "--socket-group tenuo" in unit
    assert "--socket-mode 0660" in unit
    plist = cli_mod.launchd_plist_template(cfg)
    assert "--socket-group tenuo" in plist
    assert "--socket-mode 0660" in plist


def test_service_units_create_root_owned_socket_dir(cli_mod, make_cfg, fleet):
    """systemd/launchd must create the socket's parent dir root-owned before the
    daemon binds, so `_safe_managed_socket`'s dir-ownership invariant holds."""
    sock_dir = os.path.dirname(cli_mod.DEFAULT_AUTHZ_SOCKET)
    unit = cli_mod.systemd_unit_template(make_cfg())
    assert f"RuntimeDirectory={os.path.basename(sock_dir)}" in unit
    assert "RuntimeDirectoryMode=0755" in unit
    plist = cli_mod.launchd_plist_template(make_cfg())
    assert f"mkdir -p {sock_dir}" in plist and "--socket" in plist


def test_macos_launchd_runs_native_not_docker(cli_mod, make_cfg, fleet):
    """macOS Docker Desktop runs the container in a Linux VM, so a container UDS is
    unreachable from the macOS host. The launchd daemon must run a NATIVE authorizer
    (with a loud placeholder for its path) and never `docker`."""
    plist = cli_mod.launchd_plist_template(make_cfg())
    assert "/usr/bin/docker" not in plist and "docker run" not in plist
    assert cli_mod._NATIVE_BIN_PLACEHOLDER in plist
    assert "serve" in plist and "--socket" in plist
    # Linux systemd, by contrast, stays Docker-backed.
    assert "/usr/bin/docker" in cli_mod.systemd_unit_template(make_cfg())


def test_macos_launchd_honors_configured_binary(cli_mod, make_cfg, fleet):
    plist = cli_mod.launchd_plist_template(make_cfg(authorizer={"binary": "/opt/tenuo/bin/tenuo-authorizer"}))
    assert "/opt/tenuo/bin/tenuo-authorizer" in plist
    assert cli_mod._NATIVE_BIN_PLACEHOLDER not in plist


def test_template_root_falls_back_to_loud_placeholder(cli_mod, make_cfg, fleet):
    assert cli_mod._template_root(make_cfg()) == cli_mod._ROOT_PLACEHOLDER


def test_service_templates_carry_trust_anchor(cli_mod, make_cfg, fleet):
    unit = cli_mod.systemd_unit_template(make_cfg())
    plist = cli_mod.launchd_plist_template(make_cfg())
    assert "TENUO_TRUSTED_KEYS=" in unit and "tenuo-authorizer" in unit
    assert "com.tenuo.authorizer" in plist and "TENUO_TRUSTED_KEYS=" in plist


def test_authorizer_env_forbids_admin_key(cli_mod, make_cfg, fleet):
    env = cli_mod.authorizer_env_template(make_cfg())
    assert "NEVER an admin key" in env
    assert "TENUO_API_KEY=" in env


def test_managed_hook_blocks_under_local_dry_run(tmp_path):
    """End-to-end through the real command path: `_managed-hook` must emit a DENY
    even when local policy says `mode: dry-run` (and the managed flag is absent),
    while plain `_hook` stays observe-only. This is the P1 anchor, proven via the
    actual subprocess Claude Code would launch.

    No authorizer is running (port points nowhere) so enforcement fails closed to
    deny — exactly the managed behavior we want to assert.
    """
    (tmp_path / "tenuo.yaml").write_text("name: t\nsandbox: ./ws\nmode: dry-run\ndefault: deny\n")
    # Clean TENUO_* env (no cloud creds, no stray managed flag); point at a dead port.
    env = {k: v for k, v in os.environ.items() if not k.startswith("TENUO_")}
    env["TENUO_AUTHORIZER_PORT"] = "59999"
    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo hi"}})

    def run(subcommand: str) -> str:
        return subprocess.run(
            [sys.executable, "-m", "tenuo_claude_code.cli", subcommand],
            cwd=tmp_path, input=event, capture_output=True, text=True, env=env, timeout=60,
        ).stdout

    assert '"permissionDecision": "deny"' in run("_managed-hook")
    # Contrast: plain _hook honors local dry-run -> neutral, no permissionDecision.
    assert "permissionDecision" not in run("_hook")


def test_managed_artifacts_bundle(cli_mod, make_cfg, fleet):
    arts = cli_mod._managed_artifacts(make_cfg(mcp={"downstream": "files-server"}))
    assert set(arts) == {
        cli_mod.MANAGED_SETTINGS_NAME, cli_mod.MANAGED_MCP_NAME,
        cli_mod.SYSTEMD_UNIT_NAME, cli_mod.LAUNCHD_PLIST_NAME, cli_mod.AUTHZ_ENV_NAME,
    }
    # managed-settings.json is valid JSON with the lockdown keys.
    parsed = json.loads(arts[cli_mod.MANAGED_SETTINGS_NAME])
    assert parsed["allowManagedHooksOnly"] is True


def test_managed_artifacts_linux_excludes_launchd(cli_mod, make_cfg, fleet):
    """A Linux rollout must not ship the macOS plist (and its native-binary placeholder
    noise) — only the systemd/Docker unit alongside the shared artifacts."""
    arts = cli_mod._managed_artifacts(make_cfg(), platform="linux")
    assert cli_mod.SYSTEMD_UNIT_NAME in arts
    assert cli_mod.LAUNCHD_PLIST_NAME not in arts


def test_managed_artifacts_macos_excludes_systemd(cli_mod, make_cfg, fleet):
    """A macOS rollout must not ship the Linux Docker/systemd unit — only the native
    launchd plist alongside the shared artifacts."""
    arts = cli_mod._managed_artifacts(make_cfg(), platform="macos")
    assert cli_mod.LAUNCHD_PLIST_NAME in arts
    assert cli_mod.SYSTEMD_UNIT_NAME not in arts


def test_authorizer_bin_flag_bakes_native_path(cli_mod, make_cfg, fleet):
    """--authorizer-bin must resolve the macOS plist's native binary so admins don't
    hand-edit the placeholder (DX footgun)."""
    cfg = make_cfg()
    cfg.setdefault("authorizer", {})["binary"] = "/opt/tenuo/bin/tenuo-authorizer"
    assert cli_mod._template_native_bin(cfg) == "/opt/tenuo/bin/tenuo-authorizer"
    plist = cli_mod.launchd_plist_template(cfg)
    assert "/opt/tenuo/bin/tenuo-authorizer" in plist
    assert cli_mod._NATIVE_BIN_PLACEHOLDER not in plist


def test_socket_group_flag_hardens_generated_unit(cli_mod, make_cfg, fleet, monkeypatch, capsys):
    """`managed-template --socket-group` wires the group end-to-end into the generated
    systemd unit (root-owned socket, group-restricted 0660 connect mode) without the
    admin hand-editing tenuo.yaml."""
    monkeypatch.setattr(cli_mod, "load_config", lambda: make_cfg())
    args = SimpleNamespace(bin=None, authorizer_bin=None, socket_group="tenuo",
                           platform="linux", target="systemd", out=None)
    cli_mod.cmd_managed_template(args)
    unit = capsys.readouterr().out
    assert "--socket-group tenuo" in unit
    assert "--socket-mode 0660" in unit
